import time
import dns.tsigkeyring
import dns.update
import logging
import socket
import uuid
import gssapi

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Length
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from dns import rcode
from dns.tsig import GSS_TSIG, HMAC_MD5, HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
from netaddr import IPNetwork, ip
from typing import Optional

from ipam.fields import IPNetworkField
from ipam.models import IPAddress
from .utils import normalize_fqdn
from .validators import HostnameAddressValidator, HostnameValidator, validate_base64, MinValueValidator, MaxValueValidator

logger = logging.getLogger('netbox_ddns')

TSIG_ALGORITHM_CHOICES = (
    (str(HMAC_MD5), 'HMAC MD5'),
    (str(HMAC_SHA1), 'HMAC SHA1'),
    (str(HMAC_SHA224), 'HMAC SHA224'),
    (str(HMAC_SHA256), 'HMAC SHA256'),
    (str(HMAC_SHA384), 'HMAC SHA384'),
    (str(HMAC_SHA512), 'HMAC SHA512'),
    (str(GSS_TSIG), 'GSS TSIG'),
)

ACTION_CREATE = 1
ACTION_DELETE = 2

ACTION_CHOICES = (
    (ACTION_CREATE, 'Create'),
    (ACTION_DELETE, 'Delete'),
)

# Use a private rcode for internal errors
RCODE_NO_ZONE = 4095


def get_rcode_display(code):
    if code is None:
        return None
    elif code == rcode.NOERROR:
        return _('Success')
    elif code == rcode.SERVFAIL:
        return _('Server failure')
    elif code == rcode.NXDOMAIN:
        return _('Name does not exist')
    elif code == rcode.NOTIMP:
        return _('Not implemented')
    elif code == rcode.REFUSED:
        return _('Refused')
    elif code == rcode.NOTAUTH:
        return _('Server not authoritative')
    elif code == RCODE_NO_ZONE:
        return _('No zone configured')
    else:
        return _('Unknown response: {}').format(code)


class Server(models.Model):
    server = models.CharField(
        verbose_name=_('DDNS Server'),
        max_length=255,
        validators=[HostnameAddressValidator()],
    )
    server_port = models.PositiveIntegerField(
        verbose_name=_('Server Port'),
        default=53,
        validators=[
            MinValueValidator(53),
            MaxValueValidator(65535),
        ]
    )
    tsig_key_name = models.CharField(
        verbose_name=_('TSIG Key Name'),
        max_length=255,
        validators=[HostnameValidator()],
        blank=True,
    )
    tsig_algorithm = models.CharField(
        verbose_name=_('TSIG Algorithm'),
        max_length=32,  # Longest is 24 chars for historic reasons, new ones are shorter, so 32 is more than enough
        choices=TSIG_ALGORITHM_CHOICES,
    )
    tsig_key = models.CharField(
        verbose_name=_('TSIG Key'),
        max_length=512,
        validators=[validate_base64],
        help_text=_('in base64 notation'),
    )

    tsig_gss_keyring = None

    class Meta:
        unique_together = (
            ('server', 'tsig_key_name'),
        )
        ordering = ('server', 'tsig_key_name')
        verbose_name = _('dynamic DNS Server')
        verbose_name_plural = _('dynamic DNS Servers')

    def __str__(self):
        return f'{self.server} ({self.tsig_key_name})'

    def clean(self):
        # Remove trailing dots from the server name/address
        self.server = self.server.lower().rstrip('.')

        # Ensure trailing dots from domain-style fields
        if self.tsig_algorithm != str(GSS_TSIG):
            self.tsig_key_name = normalize_fqdn(self.tsig_key_name.lower().rstrip('.'))

        # Ensure KerberosServer is set if GSS_TSIG is used
        if self.tsig_algorithm == str(GSS_TSIG):
            self.gss_tsig_init_ctx()
        else:
            if not self.tsig_key_name:
                raise ValidationError("'TSIG Key Name' is required when GSS TSIG is not used as TSIG Algorithm")

    @property
    def address(self) -> Optional[str]:
        addrinfo = socket.getaddrinfo(self.server, self.server_port, proto=socket.IPPROTO_UDP)
        for family, _, _, _, sockaddr in addrinfo:
            if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0]:
                return sockaddr[0]

    @property
    def keyring(self):
        if self.tsig_algorithm == str(GSS_TSIG):
            return self.tsig_gss_keyring

        return dns.tsigkeyring.from_text({self.tsig_key_name: self.tsig_key})

    def create_update(self, zone: str) -> dns.update.Update:
        return dns.update.Update(
            zone=normalize_fqdn(zone),
            keyring=self.keyring,
            keyname=self.tsig_key_name,
            keyalgorithm=self.tsig_algorithm
        )

    @staticmethod
    def _build_tkey_query(token, keyring, keyname):
        # make TKEY record
        inception_time = int(time.time())
        tkey = dns.rdtypes.ANY.TKEY.TKEY(
            dns.rdataclass.ANY,
            dns.rdatatype.TKEY,
            dns.name.from_text('gss-tsig.'),
            inception_time,
            inception_time,
            3,
            dns.rcode.NOERROR,
            token,
            b''
        )

        # make TKEY query
        tkey_query = dns.message.make_query(
            keyname,
            dns.rdatatype.RdataType.TKEY,
            dns.rdataclass.RdataClass.ANY
        )

        # create RRSET and add TKEY record
        rrset = tkey_query.find_rrset(
            tkey_query.additional,
            keyname,
            dns.rdataclass.RdataClass.ANY,
            dns.rdatatype.RdataType.TKEY,
            create=True
        )
        rrset.add(tkey)
        tkey_query.keyring = keyring
        return tkey_query

    def gss_tsig_init_ctx(self):
        server_ip = socket.gethostbyname(self.server)

        # generate random name
        random = uuid.uuid4()
        keyname = dns.name.from_text(f"{random}")
        spn = gssapi.Name(f'DNS@{self.server}', gssapi.NameType.hostbased_service)

        # create gssapi security context and TSIG keyring
        client_ctx = gssapi.SecurityContext(name=spn, usage='initiate')
        tsig_key = dns.tsig.Key(keyname, client_ctx, 'gss-tsig.')
        keyring = dns.tsigkeyring.from_text({})
        keyring[keyname] = tsig_key
        keyring = dns.tsig.GSSTSigAdapter(keyring)

        # perform GSS-API TKEY Exchange
        token = client_ctx.step()
        logging.info('token -> %s', token)
        logging.info('keyname -> %s', keyname)
        logging.info('keyring -> %s', keyring)
        while not client_ctx.complete:
            tkey_query = Server._build_tkey_query(token, keyring, keyname)
            response = dns.query.tcp(tkey_query, server_ip, timeout=10, port=53)
            if not client_ctx.complete:
                token = client_ctx.step(response.answer[0][0].key)
        self.keyring = keyring
        self.tsig_gss_keyring = keyname

class ZoneQuerySet(models.QuerySet):
    def find_for_dns_name(self, dns_name: str) -> Optional['Zone']:
        # Generate all possible zones
        zones = []
        parts = dns_name.lower().split('.')
        for i in range(len(parts)):
            zones.append('.'.join(parts[-i - 1:]))

        # Find the zone, if any
        return self.filter(name__in=zones).order_by(Length('name').desc()).first()


class Zone(models.Model):
    name = models.CharField(
        verbose_name=_('zone name'),
        max_length=255,
        validators=[HostnameValidator()],
        unique=True,
    )
    ttl = models.PositiveIntegerField(
        verbose_name=_('TTL'),
    )
    server = models.ForeignKey(
        to=Server,
        verbose_name=_('DDNS Server'),
        on_delete=models.PROTECT,
    )

    objects = ZoneQuerySet.as_manager()

    class Meta:
        ordering = ('name',)
        verbose_name = _('forward zone')
        verbose_name_plural = _('forward zones')

    def __str__(self):
        return self.name

    def clean(self):
        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)

    def get_updater(self):
        return self.server.create_update(self.name)


class ReverseZoneQuerySet(models.QuerySet):
    def find_for_address(self, address: ip.IPAddress) -> Optional['ReverseZone']:
        # Find the zone, if any
        zones = list(ReverseZone.objects.filter(prefix__net_contains=address))
        if not zones:
            return None

        zones.sort(key=lambda zone: zone.prefix.prefixlen)
        return zones[-1]


class ReverseZone(models.Model):
    prefix = IPNetworkField(
        verbose_name=_('prefix'),
        unique=True,
    )
    name = models.CharField(
        verbose_name=_('reverse zone name'),
        max_length=255,
        blank=True,
        help_text=_("RFC 2317 style reverse DNS, required when the prefix doesn't map to a reverse zone"),
    )
    ttl = models.PositiveIntegerField(
        verbose_name=_('TTL'),
    )
    server = models.ForeignKey(
        to=Server,
        verbose_name=_('DDNS Server'),
        on_delete=models.PROTECT,
    )

    objects = ReverseZoneQuerySet.as_manager()

    class Meta:
        ordering = ('prefix',)
        verbose_name = _('reverse zone')
        verbose_name_plural = _('reverse zones')

    def __str__(self):
        return f'for {self.prefix}'

    def record_name(self, address: ip.IPAddress):
        record_name = self.name
        if IPNetwork(self.prefix).version == 4:
            for pos, octet in enumerate(address.words):
                if (pos + 1) * 8 <= self.prefix.prefixlen:
                    continue

                record_name = f'{octet}.{record_name}'
        else:
            nibbles = f'{address.value:032x}'
            for pos, nibble in enumerate(nibbles):
                if (pos + 1) * 4 <= self.prefix.prefixlen:
                    continue

                record_name = f'{nibble}.{record_name}'

        return record_name

    def clean(self):
        if isinstance(self.prefix, IPNetwork) and self.prefix.version == 4:
            if self.prefix.prefixlen not in [0, 8, 16, 24] and not self.name:
                raise ValidationError({
                    'name': _('Required when prefix length is not 0, 8, 16 or 24'),
                })
            elif not self.name:
                # Generate it for the user
                self.name = 'in-addr.arpa'
                for pos, octet in enumerate(self.prefix.ip.words):
                    if pos * 8 >= self.prefix.prefixlen:
                        break

                    self.name = f'{octet}.{self.name}'

        elif isinstance(self.prefix, IPNetwork) and self.prefix.version == 6:
            if self.prefix.prefixlen % 4 != 0 and not self.name:
                raise ValidationError({
                    'name': _('Required when prefix length is not a nibble boundary'),
                })
            elif not self.name:
                # Generate it for the user
                self.name = 'ip6.arpa'
                nibbles = f'{self.prefix.ip.value:032x}'
                for pos, nibble in enumerate(nibbles):
                    if pos * 4 >= self.prefix.prefixlen:
                        break

                    self.name = f'{nibble}.{self.name}'

        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)


class DNSStatus(models.Model):
    ip_address = models.OneToOneField(
        to=IPAddress,
        verbose_name=_('IP address'),
        on_delete=models.CASCADE,
    )

    last_update = models.DateTimeField(
        verbose_name=_('last update'),
        auto_now=True,
    )

    forward_action = models.PositiveSmallIntegerField(
        verbose_name=_('forward record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    forward_rcode = models.PositiveIntegerField(
        verbose_name=_('forward record response'),
        blank=True,
        null=True,
    )

    reverse_action = models.PositiveSmallIntegerField(
        verbose_name=_('reverse record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    reverse_rcode = models.PositiveIntegerField(
        verbose_name=_('reverse record response'),
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = _('DNS status')
        verbose_name_plural = _('DNS status')

    def get_forward_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.forward_rcode)

    def get_forward_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.forward_rcode)
        colour = 'green' if self.forward_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)

    def get_reverse_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.reverse_rcode)

    def get_reverse_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.reverse_rcode)
        colour = 'green' if self.reverse_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)


class ExtraDNSName(models.Model):
    ip_address = models.ForeignKey(
        to=IPAddress,
        verbose_name=_('IP address'),
        on_delete=models.CASCADE,
    )
    name = models.CharField(
        verbose_name=_('DNS name'),
        max_length=255,
        validators=[HostnameValidator()],
    )

    last_update = models.DateTimeField(
        verbose_name=_('last update'),
        auto_now=True,
    )

    forward_action = models.PositiveSmallIntegerField(
        verbose_name=_('forward record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    forward_rcode = models.PositiveIntegerField(
        verbose_name=_('forward record response'),
        blank=True,
        null=True,
    )

    before_save = None

    class Meta:
        unique_together = (
            ('ip_address', 'name'),
        )
        verbose_name = _('extra DNS name')
        verbose_name_plural = _('extra DNS names')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('plugins:netbox_ddns:extradnsname_edit', args=[self.ip_address.pk, self.pk])

    def clean(self):
        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)

    def get_forward_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.forward_rcode)

    def get_forward_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.forward_rcode)
        colour = 'green' if self.forward_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)

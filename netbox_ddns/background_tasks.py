import logging
from typing import Optional

import dns.query
import dns.rdatatype
import dns.resolver
from django.db.models.functions import Length
from django_rq import job
from netaddr.ip import IPAddress

from netbox_ddns.models import ReverseZone, Zone

logger = logging.getLogger('netbox_ddns')


def get_zone(dns_name: str) -> Optional[Zone]:
    # Generate all possible zones
    zones = []
    parts = dns_name.lower().split('.')
    for i in range(len(parts)):
        zones.append('.'.join(parts[-i - 1:]))

    # Find the zone, if any
    return Zone.objects.filter(name__in=zones).order_by(Length('name').desc()).first()


def get_soa(dns_name: str) -> str:
    parts = dns_name.rstrip('.').split('.')
    for i in range(len(parts)):
        zone_name = '.'.join(parts[i:])

        try:
            dns.resolver.query(zone_name + '.', dns.rdatatype.SOA)
            return zone_name
        except dns.resolver.NoAnswer:
            # The name exists, but has no SOA. Continue one level further up
            continue
        except dns.resolver.NXDOMAIN as e:
            # Look for a SOA record in the authority section
            for query, response in e.responses().items():
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        return rrset.name.to_text(omit_final_dot=True)


def get_reverse_zone(address: IPAddress) -> Optional[ReverseZone]:
    # Find the zone, if any
    zones = list(ReverseZone.objects.filter(prefix__net_contains=address))
    if not zones:
        return None

    zones.sort(key=lambda zone: zone.prefix.prefixlen)
    return zones[-1]


def update_status(status: list, operation: str, response) -> None:
    rcode = response.rcode()

    if rcode == dns.rcode.NOERROR:
        message = f"{operation} successful"
        logger.info(message)
    else:
        message = f"{operation} failed: {dns.rcode.to_text(rcode)}"
        logger.error(message)

    status.append(message)


@job
def update_dns(old_address: IPAddress = None, new_address: IPAddress = None,
               old_dns_name: str = '', new_dns_name: str = '',
               skip_forward=False, skip_reverse=False):
    status = []

    # Only delete old records when they are provided and not the same as the new records
    if old_dns_name and old_address and (old_dns_name != new_dns_name or old_address != new_address):
        # Delete old forward record
        if not skip_forward:
            zone = get_zone(old_dns_name)
            if zone:
                logger.debug(f"Found zone {zone.name} for {old_dns_name}")

                # Check the SOA, we don't want to write to a parent zone if it has delegated authority
                soa = get_soa(old_dns_name)
                if soa == zone.name:
                    update = zone.server.create_update(zone.name)
                    update.delete(
                        old_dns_name + '.',
                        'a' if old_address.version == 4 else 'aaaa',
                        str(old_address)
                    )
                    response = dns.query.udp(update, zone.server.address)
                    update_status(status, f'Deleting {old_dns_name} {old_address}', response)
                else:
                    logger.debug(f"Can't update zone {zone.name} for {old_dns_name}, "
                                 f"it has delegated authority for {soa}")
            else:
                logger.debug(f"No zone found for {old_dns_name}")

        # Delete old reverse record
        if not skip_reverse:
            zone = get_reverse_zone(old_address)
            if zone:
                record_name = zone.record_name(old_address)
                logger.debug(f"Found zone {zone.name} for {record_name}")

                # Check the SOA, we don't want to write to a parent zone if it has delegated authority
                soa = get_soa(record_name)
                if soa == zone.name:
                    update = zone.server.create_update(zone.name)
                    update.delete(
                        record_name + '.',
                        'ptr',
                        old_dns_name + '.'
                    )
                    response = dns.query.udp(update, zone.server.address)
                    update_status(status, f'Deleting {record_name} {old_dns_name}', response)
                else:
                    logger.debug(f"Can't update zone {zone.name} for {record_name}, "
                                 f"it has delegated authority for {soa}")
            else:
                logger.debug(f"No zone found for {old_address}")

    # Always try to add, just in case a previous update failed
    if new_dns_name and new_address:
        # Add new forward record
        if not skip_forward:
            zone = get_zone(new_dns_name)
            if zone:
                logger.debug(f"Found zone {zone.name} for {new_dns_name}")

                # Check the SOA, we don't want to write to a parent zone if it has delegated authority
                soa = get_soa(new_dns_name)
                if soa == zone.name:
                    update = zone.server.create_update(zone.name)
                    update.add(
                        new_dns_name + '.',
                        zone.ttl,
                        'a' if new_address.version == 4 else 'aaaa',
                        str(new_address)
                    )
                    response = dns.query.udp(update, zone.server.address)
                    update_status(status, f'Adding {new_dns_name} {new_address}', response)
                else:
                    logger.debug(f"Can't update zone {zone.name} for {old_dns_name}, "
                                 f"it has delegated authority for {soa}")
            else:
                logger.debug(f"No zone found for {new_dns_name}")

        # Add new reverse record
        if not skip_reverse:
            zone = get_reverse_zone(new_address)
            if zone:
                record_name = zone.record_name(new_address)
                logger.debug(f"Found zone {zone.name} for {record_name}")

                # Check the SOA, we don't want to write to a parent zone if it has delegated authority
                soa = get_soa(record_name)
                if soa == zone.name:
                    update = zone.server.create_update(zone.name)
                    update.add(
                        record_name + '.',
                        zone.ttl,
                        'ptr',
                        new_dns_name + '.'
                    )
                    response = dns.query.udp(update, zone.server.address)
                    update_status(status, f'Adding {record_name} {old_dns_name}', response)
                else:
                    logger.debug(f"Can't update zone {zone.name} for {record_name}, "
                                 f"it has delegated authority for {soa}")
            else:
                logger.debug(f"No zone found for {new_address}")

    return ', '.join(status)

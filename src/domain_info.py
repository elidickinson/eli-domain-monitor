"""Domain information data structures and utilities."""

class DomainInfo:
    """Class to store domain information and status."""

    def __init__(self, domain: str):
        self.domain = domain
        self.expiration_date = None
        self.days_until_expiration = None
        self.status = []
        self.nameservers = []
        self.is_expired = False
        self.has_concerning_status = False
        self.nameservers_changed = False
        self.added_nameservers = []
        self.removed_nameservers = []
        self.error = None

        # Resolution tracking
        self.apex_ips = []
        self.www_ips = []
        self.apex_changed = False
        self.www_changed = False
        self.apex_added_ips = []
        self.apex_removed_ips = []
        self.www_added_ips = []
        self.www_removed_ips = []
        self.domain_not_exist = False  # True if domain doesn't exist (NXDOMAIN)

    def __str__(self) -> str:
        if self.error:
            return f"{self.domain}: ERROR - {self.error}"

        # Check for domain not existing
        if self.domain_not_exist:
            return f"{self.domain}: DOMAIN DOES NOT EXIST (NXDOMAIN)"

        # Check if this is a subdomain (simple check for more than 2 parts)
        is_subdomain = len(self.domain.split('.')) > 2
        
        if is_subdomain:
            # For subdomains, we only show resolution info
            resolution_parts = []
            if self.apex_ips:
                resolution_parts.append(f"resolves to: {', '.join(self.apex_ips)}")
            else:
                resolution_parts.append("resolves to: none")
            
            # Change notifications for subdomains
            change_parts = []
            if self.apex_changed:
                added_str = f"IPs ADDED: {', '.join(self.apex_added_ips)}" if self.apex_added_ips else ""
                removed_str = f"IPs REMOVED: {', '.join(self.apex_removed_ips)}" if self.apex_removed_ips else ""
                change_sub_parts = [p for p in [added_str, removed_str] if p]
                if change_sub_parts:
                    change_parts.append('; '.join(change_sub_parts))
                else:
                    change_parts.append("RESOLUTION CHANGED")
            
            change_str = f" [{'; '.join(change_parts)}]" if change_parts else ""
            
            return f"{self.domain} (subdomain): {'; '.join(resolution_parts)}{change_str}"

        # Handle case where expiration_date might be None
        if self.expiration_date and self.days_until_expiration is not None:
            expiry_str = (f"expires in {self.days_until_expiration} days "
                          f"({self.expiration_date.strftime('%Y-%m-%d')})")
        else:
            expiry_str = "expiration: unknown"

        status_str = f"status: {', '.join(self.status)}"
        ns_str = f"nameservers: {', '.join(self.nameservers)}"

        # Resolution info
        resolution_parts = []
        if self.apex_ips:
            resolution_parts.append(f"apex: {', '.join(self.apex_ips)}")
        if self.www_ips:
            resolution_parts.append(f"www: {', '.join(self.www_ips)}")
        resolution_str = f"resolves: {'; '.join(resolution_parts)}" if resolution_parts else "resolves: none"

        # Change notifications
        change_parts = []

        # Nameserver changes
        if self.nameservers_changed:
            added_str = f"NS ADDED: {', '.join(self.added_nameservers)}" if self.added_nameservers else ""
            removed_str = f"NS REMOVED: {', '.join(self.removed_nameservers)}" if self.removed_nameservers else ""
            ns_change_parts = [p for p in [added_str, removed_str] if p]
            if ns_change_parts:
                change_parts.append('; '.join(ns_change_parts))
            else:
                change_parts.append("NS CHANGED")

        # Apex resolution changes
        if self.apex_changed:
            added_str = f"APEX ADDED: {', '.join(self.apex_added_ips)}" if self.apex_added_ips else ""
            removed_str = f"APEX REMOVED: {', '.join(self.apex_removed_ips)}" if self.apex_removed_ips else ""
            apex_change_parts = [p for p in [added_str, removed_str] if p]
            if apex_change_parts:
                change_parts.append('; '.join(apex_change_parts))
            else:
                change_parts.append("APEX CHANGED")

        # WWW resolution changes
        if self.www_changed:
            added_str = f"WWW ADDED: {', '.join(self.www_added_ips)}" if self.www_added_ips else ""
            removed_str = f"WWW REMOVED: {', '.join(self.www_removed_ips)}" if self.www_removed_ips else ""
            www_change_parts = [p for p in [added_str, removed_str] if p]
            if www_change_parts:
                change_parts.append('; '.join(www_change_parts))
            else:
                change_parts.append("WWW CHANGED")

        change_str = f" [{'; '.join(change_parts)}]" if change_parts else ""

        return f"{self.domain}: {expiry_str}, {status_str}, {ns_str}, {resolution_str}{change_str}"

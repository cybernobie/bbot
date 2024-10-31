from bbot.modules.base import BaseModule

class whodat(BaseModule):
    """WHOIS and RDAP lookup module using Who Dat API"""

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_WHOIS", "DNS_RDAP"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query Who Dat API for WHOIS and RDAP information",
        "created_date": "2024-03-21",
        "author": "@Aconite33",
    }

    base_url = "https://who-dat.as93.net"

    async def setup(self):
        """Verify API is accessible"""
        try:
            # Test API with a known domain
            test_domain = "example.com"
            r = await self.api_request(f"{self.base_url}/{test_domain}")
            if r.status_code != 200:
                return None, f"API test failed with status code {r.status_code}"
            return True
        except Exception as e:
            return None, f"API test failed: {str(e)}"

    async def handle_event(self, event):
        """Handle incoming DNS_NAME events"""
        
        # Extract root domain
        _, domain = self.helpers.split_domain(event.data)
        if not domain:
            self.debug(f"Could not extract domain from {event.data}")
            return

        try:
            # Query WHOIS data
            r = await self.api_request(f"{self.base_url}/{domain}")
            
            if r.status_code == 200:
                whois_data = r.json()
                
                # Create WHOIS event
                whois_event = self.make_event({
                    "domain": domain,
                    "registrar": whois_data.get("registrar", {}),
                    "registrant": whois_data.get("registrant", {}),
                    "administrative": whois_data.get("administrative", {}),
                    "technical": whois_data.get("technical", {}),
                    "billing": whois_data.get("billing", {}),
                    "domain_info": whois_data.get("domain", {})
                }, "DNS_WHOIS", parent=event)
                
                if whois_event:
                    await self.emit_event(whois_event)
                    self.verbose(f"Retrieved WHOIS data for {domain}")

                # Create RDAP event
                rdap_event = self.make_event({
                    "domain": domain,
                    "handle": whois_data.get("domain", {}).get("id"),
                    "status": whois_data.get("domain", {}).get("status", []),
                    "nameservers": whois_data.get("domain", {}).get("name_servers", []),
                    "entities": [
                        {"role": role, "info": info}
                        for role, info in whois_data.items()
                        if role in ["registrar", "registrant", "administrative", "technical", "billing"]
                        and info
                    ],
                    "events": {
                        "registration": whois_data.get("domain", {}).get("created_date"),
                        "expiration": whois_data.get("domain", {}).get("expiration_date"),
                        "last_update": whois_data.get("domain", {}).get("updated_date")
                    }
                }, "DNS_RDAP", parent=event)
                
                if rdap_event:
                    await self.emit_event(rdap_event)
                    self.verbose(f"Created RDAP data for {domain}")

            elif r.status_code == 404:
                self.verbose(f"No WHOIS data found for {domain}")
            else:
                self.warning(f"Error retrieving WHOIS data for {domain}: {r.status_code}")

        except Exception as e:
            self.warning(f"Error processing {domain}: {str(e)}")
            self.debug(f"Error details:", trace=True)
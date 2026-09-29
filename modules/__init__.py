"""
PHANTOM RECON — Modules Package
================================
All reconnaissance modules for convenient import.
Each module is self-contained and independently usable.
"""

from .whois_module     import WhoisModule
from .dns_module       import DNSModule
from .subdomain_module import SubdomainModule
from .email_module     import EmailModule
from .shodan_module    import ShodanModule
from .tech_module      import TechModule
from .ssl_module       import SSLModule
from .port_module      import PortModule
from .osint_module     import OsintModule
from .cloud_module     import CloudModule
from .report_module    import ReportModule

__all__ = ['WhoisModule', 'DNSModule', 'SubdomainModule', 'EmailModule',
           'ShodanModule', 'TechModule', 'SSLModule', 'PortModule',
           'OsintModule', 'CloudModule', 'ReportModule']

__version__ = '2.1.0'
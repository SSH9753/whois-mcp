from . import whois_server
import asyncio

def main():
   """Main entry point for the package."""
   whois_server.main()

# Expose important items at package level
__all__ = ['main', 'whois_server']
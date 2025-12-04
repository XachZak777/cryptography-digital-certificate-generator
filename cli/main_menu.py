"""
Interactive Main Menu for Certificate Authority and Secure Communication System
Provides a user-friendly interface to interact with the system.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ca import CertificateAuthority
from server import SecureServer
from client import SecureClient


class MainMenu:
    """Interactive menu system for the CA and secure communication system."""
    
    def __init__(self):
        """Initialize the main menu."""
        self.ca = None
        self.server = None
        self.client = None
        self.server_thread = None
        self.certificates_dir = Path("certificates")
        self.certificates_dir.mkdir(exist_ok=True)
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def print_header(self, title: str):
        """Print a formatted header."""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70 + "\n")
    
    def print_menu(self, options: dict):
        """Print a formatted menu."""
        for key, description in options.items():
            print(f"  {key}. {description}")
        print()
    
    def wait_for_input(self, prompt: str = "\nPress Enter to continue..."):
        """Wait for user input."""
        input(prompt)
    
    def main_menu(self):
        """Display the main menu."""
        while True:
            self.clear_screen()
            self.print_header("Certificate Authority & Secure Communication System")
            
            print("Welcome to the Secure CA and Client-Server System!")
            print("\nThis system provides:")
            print("  • Certificate Authority for generating and signing certificates")
            print("  • Secure server with certificate-based authentication")
            print("  • Secure client with certificate verification")
            print("  • AES-CBC encrypted communication")
            print("\nAll cryptographic operations are implemented from scratch!")
            
            options = {
                "1": "Certificate Authority (CA) Operations",
                "2": "Start Secure Server",
                "3": "Connect Secure Client",
                "4": "View System Status",
                "5": "Help & Documentation",
                "0": "Exit"
            }
            
            self.print_menu(options)
            choice = input("Select an option: ").strip()
            
            if choice == "1":
                self.ca_menu()
            elif choice == "2":
                self.server_menu()
            elif choice == "3":
                self.client_menu()
            elif choice == "4":
                self.status_menu()
            elif choice == "5":
                self.help_menu()
            elif choice == "0":
                print("\nThank you for using the Secure Communication System!")
                print("Goodbye!\n")
                break
            else:
                print("\n❌ Invalid option. Please try again.")
                self.wait_for_input()
    
    def ca_menu(self):
        """Certificate Authority operations menu."""
        while True:
            self.clear_screen()
            self.print_header("Certificate Authority Operations")
            
            # Check if CA exists
            ca_key = Path("certificates/ca_private_key.pem")
            ca_cert = Path("certificates/ca_certificate.pem")
            ca_exists = ca_key.exists() and ca_cert.exists()
            
            if ca_exists:
                print("✓ CA certificate and key found")
            else:
                print("⚠ CA certificate and key not found")
            
            options = {
                "1": "Generate New CA",
                "2": "Load Existing CA",
                "3": "Generate Server Certificate",
                "4": "List Generated Certificates",
                "0": "Back to Main Menu"
            }
            
            self.print_menu(options)
            choice = input("Select an option: ").strip()
            
            if choice == "1":
                self.generate_ca()
            elif choice == "2":
                self.load_ca()
            elif choice == "3":
                self.generate_server_cert()
            elif choice == "4":
                self.list_certificates()
            elif choice == "0":
                break
            else:
                print("\n❌ Invalid option. Please try again.")
                self.wait_for_input()
    
    def generate_ca(self):
        """Generate a new Certificate Authority."""
        self.clear_screen()
        self.print_header("Generate Certificate Authority")
        
        print("This will generate a new Certificate Authority with:")
        print("  • 2048-bit RSA key pair")
        print("  • Self-signed certificate (valid for 10 years)")
        print("  • Saved to certificates/ directory")
        print("\n⚠ Note: Key generation may take 1-3 minutes...")
        
        confirm = input("\nProceed? (y/n): ").strip().lower()
        if confirm != 'y':
            return
        
        try:
            print("\n🔄 Generating CA...")
            print("  This involves generating large prime numbers...")
            
            ca_key_path = "certificates/ca_private_key.pem"
            ca_cert_path = "certificates/ca_certificate.pem"
            
            self.ca = CertificateAuthority(ca_key_path, ca_cert_path)
            self.ca.generate_ca()
            
            print("\n✅ CA generated successfully!")
            print(f"  Private Key: {ca_key_path}")
            print(f"  Certificate: {ca_cert_path}")
            
        except Exception as e:
            print(f"\n❌ Error generating CA: {e}")
        
        self.wait_for_input()
    
    def load_ca(self):
        """Load existing CA."""
        self.clear_screen()
        self.print_header("Load Certificate Authority")
        
        ca_key_path = "certificates/ca_private_key.pem"
        ca_cert_path = "certificates/ca_certificate.pem"
        
        if not Path(ca_key_path).exists() or not Path(ca_cert_path).exists():
            print("❌ CA files not found. Please generate CA first.")
            self.wait_for_input()
            return
        
        try:
            print("🔄 Loading CA...")
            self.ca = CertificateAuthority(ca_key_path, ca_cert_path)
            self.ca.load_ca()
            print("\n✅ CA loaded successfully!")
            print(f"  Subject: {self.ca.ca_certificate.subject}")
            print(f"  Valid until: {self.ca.ca_certificate.not_after}")
        except Exception as e:
            print(f"\n❌ Error loading CA: {e}")
        
        self.wait_for_input()
    
    def generate_server_cert(self):
        """Generate a server certificate."""
        self.clear_screen()
        self.print_header("Generate Server Certificate")
        
        if self.ca is None:
            print("⚠ CA not loaded. Attempting to load...")
            try:
                self.ca = CertificateAuthority(
                    "certificates/ca_private_key.pem",
                    "certificates/ca_certificate.pem"
                )
                self.ca.load_ca()
            except:
                print("❌ Could not load CA. Please generate or load CA first.")
                self.wait_for_input()
                return
        
        server_name = input("Enter server name (e.g., localhost): ").strip()
        if not server_name:
            server_name = "localhost"
        
        print(f"\n🔄 Generating certificate for '{server_name}'...")
        print("  This may take 1-3 minutes...")
        
        try:
            key_path, cert_path = self.ca.generate_server_certificate(server_name)
            print(f"\n✅ Server certificate generated!")
            print(f"  Private Key: {key_path}")
            print(f"  Certificate: {cert_path}")
        except Exception as e:
            print(f"\n❌ Error generating certificate: {e}")
        
        self.wait_for_input()
    
    def list_certificates(self):
        """List all generated certificates."""
        self.clear_screen()
        self.print_header("Generated Certificates")
        
        cert_dir = Path("certificates")
        if not cert_dir.exists():
            print("No certificates directory found.")
            self.wait_for_input()
            return
        
        cert_files = list(cert_dir.glob("*_cert.pem"))
        key_files = list(cert_dir.glob("*_key.pem"))
        
        if not cert_files and not key_files:
            print("No certificates found.")
        else:
            print("Certificates:")
            for cert_file in sorted(cert_files):
                size = cert_file.stat().st_size
                print(f"  📜 {cert_file.name} ({size} bytes)")
            
            print("\nPrivate Keys:")
            for key_file in sorted(key_files):
                size = key_file.stat().st_size
                print(f"  🔑 {key_file.name} ({size} bytes)")
        
        self.wait_for_input()
    
    def server_menu(self):
        """Server operations menu."""
        self.clear_screen()
        self.print_header("Secure Server")
        
        server_name = input("Enter server name (default: localhost): ").strip() or "localhost"
        port = input("Enter port (default: 8443): ").strip() or "8443"
        
        try:
            port = int(port)
        except ValueError:
            print("❌ Invalid port number. Using default 8443.")
            port = 8443
        
        key_path = f"certificates/{server_name}_key.pem"
        cert_path = f"certificates/{server_name}_cert.pem"
        
        if not Path(key_path).exists() or not Path(cert_path).exists():
            print(f"\n❌ Server certificate not found: {key_path} or {cert_path}")
            print("Please generate server certificate first using CA menu.")
            self.wait_for_input()
            return
        
        print(f"\n🔄 Starting server on {server_name}:{port}...")
        print("  Press Ctrl+C to stop the server\n")
        
        try:
            self.server = SecureServer(
                host=server_name if server_name != "localhost" else "localhost",
                port=port,
                server_key_path=key_path,
                server_cert_path=cert_path
            )
            self.server.start()
        except KeyboardInterrupt:
            print("\n\n🛑 Server stopped by user.")
        except Exception as e:
            print(f"\n❌ Server error: {e}")
        
        self.wait_for_input()
    
    def client_menu(self):
        """Client operations menu."""
        self.clear_screen()
        self.print_header("Secure Client")
        
        server_host = input("Enter server host (default: localhost): ").strip() or "localhost"
        port = input("Enter port (default: 8443): ").strip() or "8443"
        
        try:
            port = int(port)
        except ValueError:
            print("❌ Invalid port number. Using default 8443.")
            port = 8443
        
        ca_cert_path = "certificates/ca_certificate.pem"
        
        if not Path(ca_cert_path).exists():
            print(f"\n❌ CA certificate not found: {ca_cert_path}")
            print("Please generate CA first using CA menu.")
            self.wait_for_input()
            return
        
        print(f"\n🔄 Connecting to {server_host}:{port}...")
        
        try:
            self.client = SecureClient(
                host=server_host,
                port=port,
                ca_cert_path=ca_cert_path
            )
            self.client.connect()
        except Exception as e:
            print(f"\n❌ Client error: {e}")
        
        self.wait_for_input()
    
    def status_menu(self):
        """Display system status."""
        self.clear_screen()
        self.print_header("System Status")
        
        cert_dir = Path("certificates")
        
        print("Certificate Files:")
        if cert_dir.exists():
            files = list(cert_dir.glob("*.pem"))
            if files:
                for f in sorted(files):
                    size = f.stat().st_size
                    exists = "✓" if f.exists() else "✗"
                    print(f"  {exists} {f.name} ({size} bytes)")
            else:
                print("  No certificate files found")
        else:
            print("  Certificates directory does not exist")
        
        print("\nRequired Files for Server:")
        server_key = Path("certificates/localhost_key.pem")
        server_cert = Path("certificates/localhost_cert.pem")
        print(f"  {'✓' if server_key.exists() else '✗'} Server private key")
        print(f"  {'✓' if server_cert.exists() else '✗'} Server certificate")
        
        print("\nRequired Files for Client:")
        ca_cert = Path("certificates/ca_certificate.pem")
        print(f"  {'✓' if ca_cert.exists() else '✗'} CA certificate")
        
        self.wait_for_input()
    
    def help_menu(self):
        """Display help and documentation."""
        self.clear_screen()
        self.print_header("Help & Documentation")
        
        print("""
QUICK START GUIDE
=================

1. Generate Certificate Authority:
   - Select option 1 from main menu
   - Choose "Generate New CA"
   - Wait for key generation (1-3 minutes)

2. Generate Server Certificate:
   - Select option 1 from main menu
   - Choose "Generate Server Certificate"
   - Enter server name (e.g., localhost)

3. Start Server:
   - Select option 2 from main menu
   - Enter server details
   - Server will listen for connections

4. Connect Client:
   - Select option 3 from main menu
   - Enter server details
   - Verify certificate and start chatting!


SYSTEM ARCHITECTURE
===================

Certificate Authority (CA):
  • Generates RSA key pairs
  • Signs server certificates
  • Provides root of trust

Secure Server:
  • Presents certificate to clients
  • Receives encrypted session keys
  • Communicates via AES-CBC

Secure Client:
  • Verifies server certificate
  • Generates and encrypts session keys
  • Communicates via AES-CBC


CRYPTOGRAPHIC IMPLEMENTATIONS
==============================

All cryptographic operations are implemented from scratch:

• AES (Advanced Encryption Standard)
  - Full block cipher implementation
  - CBC mode with random IVs
  - 128/192/256-bit keys

• RSA Cryptosystem
  - Key generation with Miller-Rabin test
  - OAEP padding for security
  - 2048-bit keys

• PKCS#7 Padding
  - Block cipher padding
  - Secure padding/unpadding

• X.509 Certificates
  - Simplified certificate structure
  - RSA signature verification
  - Validity period checking


FILES AND DIRECTORIES
=====================

certificates/     - Certificate and key files
crypto/          - Cryptographic implementations
cli/             - Command-line interface modules


TROUBLESHOOTING
===============

Problem: "CA certificate not found"
Solution: Generate CA first using CA menu

Problem: "Server certificate not found"
Solution: Generate server certificate using CA menu

Problem: "Connection refused"
Solution: Ensure server is running before connecting client

Problem: Key generation takes too long
Solution: This is normal (1-3 minutes for 2048-bit keys)


For more information, see USAGE_GUIDE.md
        """)
        
        self.wait_for_input()


def main():
    """Main entry point for the interactive menu."""
    menu = MainMenu()
    try:
        menu.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()


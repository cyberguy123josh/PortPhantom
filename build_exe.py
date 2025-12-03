"""
PortPhantom Build Script
Creates standalone executable using PyInstaller
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


def check_dependencies():
    """Check if all required dependencies are installed"""
    print("Checking dependencies...")
    
    required = [
        'PyInstaller',
        'customtkinter',
        'scapy',
        'rich',
        'pyfiglet',
        'nvdlib'
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package.lower().replace('-', '_'))
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} - MISSING")
            missing.append(package)
    
    if missing:
        print("\n❌ Missing dependencies. Install with:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    print("✓ All dependencies installed\n")
    return True


def clean_build_dirs():
    """Clean previous build directories"""
    print("Cleaning previous build files...")
    
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"  Removed {dir_name}/")
    
    if os.path.exists('scanner_gui.spec'):
        os.remove('scanner_gui.spec')
        print("  Removed scanner_gui.spec")
    
    print("✓ Build directories cleaned\n")


def create_assets_dir():
    """Ensure assets directory exists"""
    assets_dir = Path('assets')
    assets_dir.mkdir(exist_ok=True)
    
    icon_path = assets_dir / 'icon.ico'
    if not icon_path.exists():
        print("⚠ Warning: assets/icon.ico not found")
        print("  Using default icon. Create icon.ico for custom icon.\n")
        return None
    
    return str(icon_path)


def build_executable():
    """Build the executable using PyInstaller"""
    print("Building PortPhantom.exe...")
    print("This may take several minutes...\n")
    
    icon_path = create_assets_dir()
    
    cmd = [
        'pyinstaller',
        '--name=PortPhantom',
        '--onefile',
        '--windowed',
        '--clean',
    ]
    
    if icon_path:
        cmd.append(f'--icon={icon_path}')
    
    hidden_imports = [
        'customtkinter',
        'tkinterdnd2',
        'PIL._tkinter_finder',
        'scapy.all',
        'rich.console',
        'pyfiglet',
        'nvdlib',
    ]
    
    for imp in hidden_imports:
        cmd.extend(['--hidden-import', imp])
    
    cmd.extend([
        '--add-data', 'config_manager.py;.',
        '--add-data', 'engine_adapter.py;.',
        '--add-data', 'features.py;.',
        '--add-data', 'scanner.py;.',
    ])
    
    if os.path.exists('assets'):
        cmd.extend(['--add-data', 'assets;assets'])
    
    cmd.append('scanner_gui.py')
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        print("✓ Build completed successfully!\n")
        return True
    except subprocess.CalledProcessError as e:
        print("❌ Build failed!")
        print(e.stderr)
        return False


def create_distribution():
    """Create distribution folder with necessary files"""
    print("Creating distribution package...")
    
    dist_dir = Path('dist')
    if not dist_dir.exists():
        print("❌ dist/ directory not found. Build may have failed.")
        return False
    
    package_dir = dist_dir / 'PortPhantom_Package'
    package_dir.mkdir(exist_ok=True)
    
    exe_path = dist_dir / 'PortPhantom.exe'
    if exe_path.exists():
        shutil.copy(exe_path, package_dir / 'PortPhantom.exe')
        print(f"  ✓ Copied PortPhantom.exe")
    else:
        print("  ❌ PortPhantom.exe not found")
        return False
    
    if os.path.exists('README.md'):
        shutil.copy('README.md', package_dir / 'README.md')
        print("  ✓ Copied README.md")
    
    if os.path.exists('scanner.py'):
        shutil.copy('scanner.py', package_dir / 'scanner.py')
        print("  ✓ Copied scanner.py")
    
    samples_dir = package_dir / 'samples'
    samples_dir.mkdir(exist_ok=True)
    
    sample_targets = samples_dir / 'sample_targets.txt'
    with open(sample_targets, 'w') as f:
        f.write("# Sample Target List\n")
        f.write("# One target per line (IP, CIDR, or range)\n")
        f.write("# Lines starting with # are ignored\n\n")
        f.write("127.0.0.1\n")
        f.write("# 192.168.1.0/24\n")
        f.write("# 10.0.0.1-10.0.0.10\n")
    print("  ✓ Created sample_targets.txt")
    
    print(f"\n✓ Distribution package created in: {package_dir}\n")
    return True


def print_summary():
    """Print build summary"""
    print("=" * 60)
    print("BUILD COMPLETE!")
    print("=" * 60)
    
    exe_path = Path('dist/PortPhantom_Package/PortPhantom.exe')
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n📦 Executable: {exe_path}")
        print(f"📏 Size: {size_mb:.1f} MB")
        print(f"\n✅ Ready to distribute!")
        
        print("\n" + "=" * 60)
        print("NEXT STEPS:")
        print("=" * 60)
        print("1. Test the executable")
        print("2. For SYN/ACK/FIN/RST scans, install Scapy: pip install scapy")
        print("3. Run as Administrator for raw socket scans")
        print("4. Distribute the PortPhantom_Package folder")
        print("\n" + "=" * 60)
    else:
        print("\n❌ Build failed - executable not found")


def main():
    """Main build process"""
    print("\n" + "=" * 60)
    print("PORTPHANTOM BUILD SCRIPT")
    print("=" * 60 + "\n")
    
    if not check_dependencies():
        sys.exit(1)
    
    clean_build_dirs()
    
    if not build_executable():
        print("\n❌ Build failed.")
        sys.exit(1)
    
    if not create_distribution():
        print("\n❌ Failed to create distribution package.")
        sys.exit(1)
    
    print_summary()


if __name__ == "__main__":
    main()

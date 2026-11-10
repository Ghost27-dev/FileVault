# FileVault

A desktop app that hides files and folders behind a password. Cross-platform (Windows/macOS/Linux), with a GUI and a full-featured CLI.

## Features

- **Hide & reveal** — password-protect any file or folder, hidden at the OS level
- **Recovery key** — reset your password if you forget it
- **Custom icons** — set a custom icon on a protected item while it's visible
- **Decoy stand-ins** — swap in a different file or folder to take an item's place while it's hidden
- **Auto-hide** — re-hide revealed items after a timeout, on app close, or at login
- **Activity log** — tracks hide, reveal, and failed-password attempts
- **Lock the app itself** — optionally require a password just to open FileVault

## Requirements

- Python 3.9+
- tkinter (bundled with Python on Windows/macOS; on Linux: `sudo apt install python3-tk` or your distro's equivalent)

## Install

```bash
git clone https://github.com/Ghost27-dev/FileVault.git
cd FileVault
python filevault.py
```

No external dependencies — just the Python standard library.

## Usage

### GUI

```bash
python filevault.py
```

First run asks you to create a password and shows a one-time recovery key — save it somewhere safe, it's the only way back in if you forget your password.

### CLI

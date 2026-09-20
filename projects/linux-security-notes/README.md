# Linux Security Notes

## Overview
Organized notes for core Linux security practices in beginner-to-intermediate defensive workflows.

## Objectives
- Reinforce practical hardening habits.
- Provide safe verification commands for lab use.
- Build repeatable administration checklists.

## Features
- Least privilege guidance.
- User/group and permission controls.
- SSH, firewall, logging, backup, and update notes.

## Technologies
- Linux
- Bash
- Markdown

## Setup
Use these notes in a test VM before applying to critical systems.

## Usage
Read each section and validate commands in an isolated lab.

## Example Output
```text
Lab check: sudo ufw status verbose
```

## Security Considerations
Some commands change security posture; test in lab and confirm authorization first.

## Lessons Learned
Small hardening checks compound into stronger baseline security.

## Future Improvements
Add distro-specific variants for Ubuntu and Fedora.

## Least Privilege
- Give users only required permissions.
- Use `sudo` instead of direct root login.

## Users and Groups
- Review accounts: `getent passwd`
- Review admin-capable users: `getent group sudo`

## Permissions
- Inspect sensitive file permissions: `ls -l /etc/shadow`
- Find world-writable files in lab: `find / -xdev -type f -perm -0002 2>/dev/null`

## Updates
- Ubuntu lab updates: `sudo apt update && sudo apt upgrade`

## SSH Hardening
- Disable root SSH login.
- Prefer key authentication.
- Test config before restart: `sudo sshd -t`

## Firewall Basics
- Enable UFW in lab: `sudo ufw enable`
- Allow only required services.

## Logging
- Check auth logs: `sudo tail -n 50 /var/log/auth.log`

## Backups
- Keep regular, tested offline backups.

## Verification Commands
- Open ports (lab): `ss -tulpen`
- Running services: `systemctl list-units --type=service --state=running`

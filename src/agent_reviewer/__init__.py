"""AI security review agent for the agentic-ai-security-lab.

Reads a (synthetic) AI agent configuration, checks it against agentic AI
threat guidance, and drafts a security review for human sign-off.
Configurations under review are untrusted input: they are treated as data,
never as instructions. Synthetic data only.
"""

__version__ = "0.0.1"

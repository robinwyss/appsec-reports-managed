"""
Utility helper functions.
"""

from pathlib import Path
import logging


def ensure_output_directory(directory: Path) -> None:
    """
    Ensure the output directory exists, create if it doesn't.
    
    Args:
        directory: Path to the directory
    """
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        logging.debug("Created output directory: %s", directory)
    else:
        logging.debug("Output directory exists: %s", directory)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing or replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Replace problematic characters
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    sanitized = filename
    for char in invalid_chars:
        sanitized = sanitized.replace(char, '_')
    return sanitized

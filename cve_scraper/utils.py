def truncate(text: str, length: int = 800) -> str:
    """Truncate text to specified length"""
    return text[:length] + "..." if len(text) > length else text

def divider() -> None:
    """Print a divider line"""
    print("─" * 60)

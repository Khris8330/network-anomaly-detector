def calculate_risk(device, known_devices):

    score = 0

    # New device
    if device["mac"] not in known_devices:
        score += 50

    # Unknown vendor
    if device.get("vendor") == "Unknown":
        score += 20

    # Example: virtual machines
    if device["mac"].startswith("52:55"):
        score += 10

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level

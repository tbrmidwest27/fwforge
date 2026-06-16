"""Palo Alto URL-filtering category -> FortiOS FortiGuard web-filter category.

FortiConverter ships a licensed PAN->FortiGuard mapping; this is a clean-room,
hand-curated map from PAN predefined URL categories to FortiGuard web-filter
category IDs. The FortiGuard IDs were VERIFIED against a live FortiGate-601F
(FortiOS 8.0.0 build0167) on 2026-06-16 via
`GET /api/v2/monitor/webfilter/fortiguard-categories`.

This is coarser than per-URL control, and PAN's risk-LEVEL buckets
(high/medium/low-risk, real-time-detection) have no FortiGuard content-category
equivalent — those, and any unmapped category, are flagged for manual handling,
never silently dropped or guessed.
"""
from __future__ import annotations

# FortiGuard web-filter category id -> name (verified live, FortiOS 8.0 b0167)
FTGD_NAME = {
    0: "Unrated", 1: "Drug Abuse", 2: "Alternative Beliefs", 3: "Hacking",
    4: "Illegal or Unethical", 5: "Discrimination", 6: "Explicit Violence",
    7: "Abortion", 8: "Other Adult Materials", 9: "Advocacy Organizations",
    11: "Gambling", 12: "Extremist Groups", 13: "Nudity and Risque",
    14: "Pornography", 15: "Dating", 16: "Weapons (Sales)", 17: "Advertising",
    18: "Brokerage and Trading", 19: "Freeware and Software Downloads",
    20: "Games", 23: "Web-based Email", 24: "File Sharing and Storage",
    25: "Streaming Media and Download", 26: "Malicious Websites",
    28: "Entertainment", 29: "Arts and Culture", 30: "Education",
    31: "Finance and Banking", 33: "Health and Wellness", 34: "Job Search",
    35: "Medicine", 36: "News and Media", 37: "Social Networking",
    38: "Political Organizations", 39: "Reference", 40: "Global Religion",
    41: "Search Engines and Portals", 42: "Shopping",
    43: "General Organizations", 44: "Society and Lifestyles", 46: "Sports",
    47: "Travel", 48: "Personal Vehicles", 49: "Business",
    50: "Information and Computer Security",
    51: "Government and Legal Organizations", 52: "Information Technology",
    53: "Armed Forces", 54: "Dynamic Content", 55: "Meaningless Content",
    56: "Web Hosting", 57: "Marijuana", 58: "Folklore", 59: "Proxy Avoidance",
    61: "Phishing", 62: "Plagiarism", 63: "Sex Education", 64: "Alcohol",
    65: "Tobacco", 66: "Lingerie and Swimsuit",
    67: "Sports Hunting and War Games", 68: "Web Chat", 69: "Instant Messaging",
    70: "Newsgroups and Message Boards", 71: "Digital Postcards",
    72: "Peer-to-peer File Sharing", 75: "Internet Radio and TV",
    76: "Internet Telephony", 77: "Child Education", 78: "Real Estate",
    79: "Restaurant and Dining", 80: "Personal Websites and Blogs",
    81: "Secure Websites", 82: "Content Servers", 83: "Child Sexual Abuse",
    84: "Web-based Applications", 85: "Domain Parking", 86: "Spam URLs",
    87: "Personal Privacy", 88: "Dynamic DNS", 89: "Auction",
    90: "Newly Observed Domain", 91: "Newly Registered Domain",
    92: "Charitable Organizations", 93: "Remote Access", 94: "Web Analytics",
    95: "Online Meeting", 96: "Terrorism", 97: "URL Shortening",
    98: "Crypto Mining", 99: "Potentially Unwanted Program",
    100: "Artificial Intelligence Technology", 101: "Cryptocurrency",
}

# PAN predefined URL category -> FortiGuard category id(s). One PAN category
# can expand to several FortiGuard categories (alcohol-and-tobacco -> both).
PAN_TO_FTGD = {
    "abortion": [7],
    "abused-drugs": [1],
    "adult": [14, 8],
    "alcohol-and-tobacco": [64, 65],
    "artificial-intelligence": [100],
    "ai-code-assistant": [100],
    "auctions": [89],
    "business-and-economy": [49],
    "command-and-control": [26],
    "computer-and-internet-info": [52],
    "content-delivery-networks": [82],
    "cryptocurrency": [101],
    "dating": [15],
    "dynamic-dns": [88],
    "educational-institutions": [30],
    "entertainment-and-arts": [28, 29],
    "extremism": [12],
    "financial-services": [31],
    "gambling": [11],
    "games": [20],
    "government": [51],
    "grayware": [99],
    "hacking": [3],
    "health-and-medicine": [33, 35],
    "home-and-garden": [44],
    "hunting-and-fishing": [67],
    "insufficient-content": [55],
    "internet-communications-and-telephony": [76],
    "internet-portals": [41],
    "job-search": [34],
    "legal": [51],
    "malware": [26],
    "military": [53],
    "motor-vehicles": [48],
    "music": [25],
    "newly-registered-domain": [91],
    "news": [36],
    "not-resolved": [0],
    "nudity": [13],
    "online-storage-and-backup": [24],
    "parked": [85],
    "peer-to-peer": [72],
    "personal-sites-and-blogs": [80],
    "philosophy-and-political-advocacy": [38, 9],
    "phishing": [61],
    "proxy-avoidance-and-anonymizers": [59],
    "questionable": [8],
    "real-estate": [78],
    "recreation-and-hobbies": [44],
    "reference-and-research": [39],
    "religion": [40],
    "remote-access": [93],
    "scanning-activity": [26],
    "search-engines": [41],
    "sex-education": [63],
    "shareware-and-freeware": [19],
    "shopping": [42],
    "social-networking": [37],
    "society": [44],
    "sports": [46],
    "stock-advice-and-tools": [18],
    "streaming-media": [25],
    "swimsuits-and-intimate-apparel": [66],
    "training-and-tools": [30],
    "travel": [47],
    "unknown": [0],
    "weapons": [16],
    "web-advertisements": [17],
    "web-based-email": [23],
    "web-hosting": [56],
}

# PAN risk-LEVEL categories: not content categories, no FortiGuard equivalent.
# Flagged with a specific message rather than mapped.
RISK_BUCKETS = {"high-risk", "medium-risk", "low-risk", "real-time-detection"}

# PAN per-category action -> FortiOS ftgd-wf action (verified enum: block,
# authenticate, monitor, warning). 'allow' has NO ftgd-wf entry (categories
# pass by default), so an allowed category produces no filter.
ACTION = {
    "block": "block",
    "continue": "warning",   # PAN "continue" = click-through warning page
    "override": "authenticate",  # PAN "override" = password to proceed
    "alert": "monitor",      # log but allow
}


def to_ftgd(pan_cat: str) -> list[int]:
    """FortiGuard category id(s) for a PAN category name, or [] if unmapped."""
    return PAN_TO_FTGD.get((pan_cat or "").strip().lower(), [])

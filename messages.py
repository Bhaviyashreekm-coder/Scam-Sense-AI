"""Bilingual (English / Tamil) message dictionary.
All user-facing text lives here, keyed by code then language.
Add one entry per indicator code, risk level, action and error key.
Have a Tamil speaker review the wording before the demo.
"""
LANGUAGES = {"en": "English", "ta": "தமிழ்"}

NO_THREAT_NOTICE = {
    "en": "No known threat was detected in the checks performed. This does not guarantee that the website is safe.",
    "ta": "மேற்கொள்ளப்பட்ட சோதனைகளில் அறியப்பட்ட அச்சுறுத்தல் எதுவும் கண்டறியப்படவில்லை. இது இணையதளம் பாதுகாப்பானது என்பதற்கான உத்தரவாதம் அல்ல.",
}

MESSAGES = {
    "IP_AS_HOST": {
        "en": {"title": "IP address used instead of a domain",
               "explanation": "Legitimate sites usually use a name, not raw numbers."},
        "ta": {"title": "டொமைனுக்கு பதிலாக IP முகவரி",
               "explanation": "நம்பகமான தளங்கள் பொதுவாக எண்களுக்கு பதிலாக பெயரைப் பயன்படுத்தும்."},
    },
    # TODO: EXCESS_SUBDOMAINS, LOOKALIKE_DOMAIN, URL_SHORTENER, MISLEADING_HTTPS,
    #       UNUSUAL_CHARS, SUSPICIOUS_PATTERN, REDIRECT_PATTERN,
    #       risk levels, recommended actions, error keys
}

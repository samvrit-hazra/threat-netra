import re
from typing import Optional, List, Tuple, Dict

# Canonical Lat/Lon Centroids for Countries, Regions & Strategic Conflict Zones
GEO_CENTROIDS: Dict[str, Tuple[float, float]] = {
    # Middle East & Levant
    "israel": (31.0461, 34.8516),
    "tel aviv": (32.0853, 34.7818),
    "jerusalem": (31.7683, 35.2137),
    "gaza": (31.5017, 34.4668),
    "west bank": (31.9522, 35.2332),
    "lebanon": (33.8547, 35.8623),
    "beirut": (33.8938, 35.5018),
    "southern lebanon": (33.2721, 35.2033),
    "iran": (32.4279, 53.6880),
    "tehran": (35.6892, 51.3890),
    "isfahan": (32.6546, 51.6680),
    "natanz": (33.5133, 51.9161),
    "syria": (34.8021, 38.9968),
    "damascus": (33.5138, 36.2765),
    "yemen": (15.5527, 48.5164),
    "sanaa": (15.3694, 44.1910),
    "hodeidah": (14.7978, 42.9545),
    "iraq": (33.2232, 43.6793),
    "baghdad": (33.3152, 44.3661),
    "red sea": (20.2802, 38.5126),
    "gulf of aden": (12.4833, 48.0000),
    "saudi arabia": (23.8859, 45.0792),
    "riyadh": (24.7136, 46.6753),
    "united arab emirates": (23.4241, 53.8478),
    "dubai": (25.2048, 55.2708),
    "abu dhabi": (24.4539, 54.3773),
    "qatar": (25.3548, 51.1839),
    "doha": (25.2854, 51.5310),
    "turkey": (38.9637, 35.2433),
    "turkiye": (38.9637, 35.2433),
    "ankara": (39.9334, 32.8597),
    "istanbul": (41.0082, 28.9784),

    # Eastern Europe & Eurasia
    "ukraine": (48.3794, 31.1656),
    "kyiv": (50.4501, 30.5234),
    "kiev": (50.4501, 30.5234),
    "kharkiv": (49.9935, 36.2304),
    "odesa": (46.4825, 30.7233),
    "crimea": (45.3453, 34.4997),
    "sevastopol": (44.6167, 33.5254),
    "donbas": (48.0000, 37.8000),
    "donetsk": (48.0159, 37.8029),
    "luhansk": (48.5740, 39.3078),
    "zaporizhzhia": (47.8388, 35.1396),
    "kursk": (51.7304, 36.1926),
    "belgorod": (50.5954, 36.5873),
    "russia": (61.5240, 105.3188),
    "moscow": (55.7558, 37.6173),
    "saint petersburg": (59.9343, 30.3351),
    "belarus": (53.7098, 27.9534),
    "minsk": (53.9006, 27.5590),
    "poland": (51.9194, 19.1451),
    "warsaw": (52.2297, 21.0122),
    "moldova": (47.4116, 28.3699),
    "estonia": (58.5953, 25.0136),
    "latvia": (56.8796, 24.6032),
    "lithuania": (55.1694, 23.8813),
    "georgia": (42.3154, 43.3569),
    "tbilisi": (41.7151, 44.8271),
    "armenia": (40.0691, 45.0382),
    "yerevan": (40.1792, 44.4991),
    "azerbaijan": (40.1431, 47.5769),
    "baku": (40.4093, 49.8671),

    # Asia & Indo-Pacific
    "taiwan": (23.6978, 120.9605),
    "taipei": (25.0330, 121.5654),
    "taiwan strait": (24.0000, 119.5000),
    "china": (35.8617, 104.1954),
    "beijing": (39.9042, 116.4074),
    "shanghai": (31.2304, 121.4737),
    "hong kong": (22.3193, 114.1694),
    "south china sea": (12.0000, 114.0000),
    "south korea": (35.9078, 127.7669),
    "seoul": (37.5665, 126.9780),
    "north korea": (40.3399, 127.5101),
    "pyongyang": (39.0392, 125.7625),
    "japan": (36.2048, 138.2529),
    "tokyo": (35.6762, 139.6503),
    "philippines": (12.8797, 121.7740),
    "manila": (14.5995, 120.9842),
    "india": (20.5937, 78.9629),
    "new delhi": (28.6139, 77.2090),
    "mumbai": (19.0760, 72.8777),
    "kashmir": (34.0837, 74.7973),
    "jammu": (32.7266, 74.8570),
    "ladakh": (34.1526, 77.5771),
    "pakistan": (30.3753, 69.3451),
    "islamabad": (33.6844, 73.0479),
    "karachi": (24.8607, 67.0011),
    "afghanistan": (33.9391, 67.7100),
    "kabul": (34.5553, 69.2075),
    "bangladesh": (23.6850, 90.3563),
    "dhaka": (23.8103, 90.4125),
    "myanmar": (21.9162, 95.9560),
    "naypyidaw": (19.7633, 96.0785),

    # Europe & UK
    "united kingdom": (55.3781, -3.4360),
    "britain": (55.3781, -3.4360),
    "uk": (55.3781, -3.4360),
    "london": (51.5074, -0.1278),
    "france": (46.2276, 2.2137),
    "paris": (48.8566, 2.3522),
    "germany": (51.1657, 10.4515),
    "berlin": (52.5200, 13.4050),
    "italy": (41.8719, 12.5674),
    "rome": (41.9028, 12.4964),
    "spain": (40.4637, -3.7492),
    "madrid": (40.4168, -3.7038),
    "netherlands": (52.1326, 5.2913),
    "the hague": (52.0705, 4.3007),
    "sweden": (60.1282, 18.6435),
    "stockholm": (59.3293, 18.0686),
    "finland": (61.9241, 25.7482),
    "helsinki": (60.1699, 24.9384),

    # Americas
    "united states": (37.0902, -95.7129),
    "usa": (37.0902, -95.7129),
    "us": (37.0902, -95.7129),
    "washington": (38.9072, -77.0369),
    "new york": (40.7128, -74.0060),
    "california": (36.7783, -119.4179),
    "texas": (31.9686, -99.9018),
    "canada": (56.1304, -106.3468),
    "ottawa": (45.4215, -75.6972),
    "mexico": (23.6345, -102.5528),
    "brazil": ( -14.2350, -51.9253),
    "brasilia": (-15.7975, -47.8919),
    "colombia": (4.5709, -74.2973),
    "venezuela": (6.4238, -66.5897),
    "caracas": (10.4806, -66.9036),

    # Africa
    "sudan": (12.8628, 30.2176),
    "khartoum": (15.5007, 32.5599),
    "somalia": (5.1521, 46.1996),
    "mogadishu": (2.0469, 45.3182),
    "nigeria": (9.0820, 8.6753),
    "abuja": (9.0765, 7.3986),
    "mali": (17.5707, -3.9962),
    "niger": (17.6078, 8.0817),
    "burkina faso": (12.2383, -1.5616),
    "ethiopia": (9.1450, 40.4897),
    "egypt": (26.8206, 30.8025),
    "cairo": (30.0444, 31.2357),
    "libya": (26.3351, 17.2283),
    "tripoli": (32.8872, 13.1913)
}

# Category Heuristics
CAT_WAR = [
    "war", "military", "missile", "drone strike", "airstrike", "artillery",
    "frontline", "combat", "invasion", "troops", "strike", "kinetic", "bombing",
    "shelling", "battle", "air defense", "ammunition", "offensive", "idf", "hamas", "hezbollah"
]
CAT_TERROR = [
    "terrorism", "terrorist", "suicide bomb", "hostage", "insurgent", "insurgency",
    "extremist", "jihadist", "isis", "al-qaeda", "car bomb", "militant", "mass casualty"
]
CAT_LEAK = [
    "data leak", "database leak", "national leak", "breached records", "citizens data",
    "classified leak", "voter records", "aadhaar", "ssn", "passport leak", "ministry leak",
    "government breach", "national registry", "cyber espionage"
]
CAT_INFRA = [
    "power grid", "blackout", "scada", "water treatment", "nuclear plant", "pipeline",
    "seaport", "airport", "rail network", "critical infrastructure", "telecom blackout"
]

def detect_threat_category(text: str) -> Optional[str]:
    lower_text = text.lower()
    if any(k in lower_text for k in CAT_WAR):
        return "war_conflict"
    if any(k in lower_text for k in CAT_TERROR):
        return "terrorism"
    if any(k in lower_text for k in CAT_LEAK):
        return "state_leak"
    if any(k in lower_text for k in CAT_INFRA):
        return "critical_infra"
    return None

def resolve_location(
    location_name: Optional[str] = None,
    text: Optional[str] = None,
    category_hint: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[List[float]], Optional[str]]:
    """
    Determines if an intelligence item is location-based (war, terrorism, state leaks, critical infra)
    and resolves its coordinates.
    Returns: (is_geolocated, canonical_location_name, [lat, lon], category)
    """
    combined = f"{location_name or ''} {text or ''}".lower()
    
    # 1. Determine category (must be a location-relevant threat category)
    category = category_hint or detect_threat_category(combined)
    if not category:
        # Check if the title or text specifically mentions war or terrorism or country leak
        return False, None, None, None

    # 2. Match location name if explicitly provided
    if location_name:
        loc_clean = location_name.strip().lower()
        # Direct lookup
        if loc_clean in GEO_CENTROIDS:
            lat, lon = GEO_CENTROIDS[loc_clean]
            return True, location_name.title(), [round(lat, 4), round(lon, 4)], category
        # Match tokens
        for key, coords in GEO_CENTROIDS.items():
            if key in loc_clean:
                return True, location_name.title(), [round(coords[0], 4), round(coords[1], 4)], category

    # 3. Match from combined text (prioritizing longer key names)
    sorted_keys = sorted(GEO_CENTROIDS.keys(), key=len, reverse=True)
    for key in sorted_keys:
        # Match as whole word
        pattern = r'\b' + re.escape(key) + r'\b'
        if re.search(pattern, combined):
            lat, lon = GEO_CENTROIDS[key]
            return True, key.title(), [round(lat, 4), round(lon, 4)], category

    return False, None, None, None

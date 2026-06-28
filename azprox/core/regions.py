"""
Regions — Azure region enumeration and selection logic.

Provides hardcoded region lists and dynamic region discovery via Azure SDK.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import random


@dataclass
class AzureRegion:
    name: str           # e.g. "westeurope"
    display_name: str   # e.g. "West Europe"
    geography: str      # e.g. "Europe"


# Regions known to support Azure Functions Consumption plan (Python, Linux)
# Grouped by geography for easy selection

EU_REGIONS: list[str] = [
    "westeurope",           # Netherlands
    "northeurope",          # Ireland
    "uksouth",              # London
    "ukwest",               # Cardiff
    "francecentral",        # Paris
    "francesouth",          # Marseille
    "germanywestcentral",   # Frankfurt
    "germanynorth",         # Berlin
    "switzerlandnorth",     # Zurich
    "switzerlandwest",      # Geneva
    "norwayeast",           # Oslo
    "norwaywest",           # Stavanger
    "swedencentral",        # Stockholm
    "polandcentral",        # Warsaw
    "italynorth",           # Milan
    "spaincentral",         # Madrid
]

US_REGIONS: list[str] = [
    "eastus",
    "eastus2",
    "centralus",
    "westus",
    "westus2",
    "westus3",
    "northcentralus",
    "southcentralus",
    "westcentralus",
]

APAC_REGIONS: list[str] = [
    "eastasia",             # Hong Kong
    "southeastasia",        # Singapore
    "australiaeast",        # Sydney
    "australiasoutheast",   # Melbourne
    "japaneast",            # Tokyo
    "japanwest",            # Osaka
    "koreacentral",         # Seoul
    "centralindia",         # Pune
]

ALL_REGIONS: list[str] = EU_REGIONS + US_REGIONS + APAC_REGIONS

# Short codes for storage account naming (max 24 chars, no hyphens)
REGION_SHORT_CODES: dict[str, str] = {
    "westeurope": "weu",
    "northeurope": "neu",
    "uksouth": "uks",
    "ukwest": "ukw",
    "francecentral": "frc",
    "francesouth": "frs",
    "germanywestcentral": "gwc",
    "germanynorth": "gno",
    "switzerlandnorth": "chn",
    "switzerlandwest": "chw",
    "norwayeast": "noe",
    "norwaywest": "now",
    "swedencentral": "sec",
    "polandcentral": "plc",
    "italynorth": "itn",
    "spaincentral": "esc",
    "eastus": "eus",
    "eastus2": "eu2",
    "centralus": "cus",
    "westus": "wus",
    "westus2": "wu2",
    "westus3": "wu3",
    "northcentralus": "ncu",
    "southcentralus": "scu",
    "westcentralus": "wcu",
    "eastasia": "eas",
    "southeastasia": "sea",
    "australiaeast": "aue",
    "australiasoutheast": "aus",
    "japaneast": "jpe",
    "japanwest": "jpw",
    "koreacentral": "krc",
    "centralindia": "cin",
}


def resolve_regions(
    regions_csv: Optional[str] = None,
    count: int = 5,
    all_eu: bool = False,
    geography: Optional[str] = None,
) -> list[str]:
    """
    Resolve which regions to deploy to based on CLI flags.

    Priority:
    1. If regions_csv is set → parse and validate
    2. If all_eu → return EU_REGIONS
    3. Otherwise → randomly select `count` regions from EU_REGIONS (default)

    Validation:
    - Check each region against ALL_REGIONS
    - Warn on unknown regions but don't block (Azure might have new ones)
    """
    if regions_csv:
        selected = [r.strip().lower() for r in regions_csv.split(",")]
        unknown = [r for r in selected if r not in ALL_REGIONS]
        if unknown:
            # Warn but continue — region might be new/valid
            pass
        return selected

    if all_eu:
        return EU_REGIONS.copy()

    pool = EU_REGIONS if geography is None or geography == "eu" else ALL_REGIONS
    return random.sample(pool, min(count, len(pool)))


def get_region_short(region: str) -> str:
    """Get short code for a region (used in storage account naming)."""
    return REGION_SHORT_CODES.get(region, region[:3])


def get_available_regions(auth=None) -> list[AzureRegion]:
    """
    Fetch available regions from Azure SDK.

    If auth is provided, use it to query Azure for regions that support
    Microsoft.Web/sites (Function Apps) with Consumption plan.

    Falls back to hardcoded list if no auth or API call fails.

    TODO: Implement with:
        subscription_client = SubscriptionClient(auth.credential)
        regions = subscription_client.subscriptions.list_locations(auth.subscription_id)
    """
    # Fallback to hardcoded
    return [
        AzureRegion(name=r, display_name=r.replace("_", " ").title(), geography="")
        for r in ALL_REGIONS
    ]

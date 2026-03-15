import random
from datetime import datetime, timedelta, time

import pandas as pd
from faker import Faker

# ----------------------------
# Reproducibility
# ----------------------------
SEED = 42
random.seed(SEED)
Faker.seed(SEED)
fake = Faker()

# ----------------------------
# Dataset parameters
# ----------------------------
TOTAL_ROWS = 500000
START_DATE = datetime(2024, 10, 1)
NOW = datetime.now().replace(microsecond=0)
RECENT_WINDOW_DAYS = 7
RECENT_WINDOW_START = NOW - timedelta(days=RECENT_WINDOW_DAYS)

COUNTRIES = ["US", "DE", "FR", "ES", "GB", "NL"]
COUNTRY_WEIGHTS = {
    "US": 1.65,
    "DE": 1.20,
    "FR": 1.00,
    "ES": 0.82,
    "GB": 0.78,
    "NL": 0.55,
}

BASE_SOURCES = ["web_form", "crm_import", "partner_api", "event_import", "LinkedinForm_2026", "FacebookForm_2026"]
SOURCE_WEIGHTS = {
    "web_form": 1.40,
    "crm_import": 1.15,
    "partner_api": 0.70,
    "event_import": 0.45,
    "LinkedinForm_2026": 0.22,
    "FacebookForm_2026": 0.18,
}

GENERIC_TITLES = [
    "Marketing Manager",
    "Sales Manager",
    "Business Analyst",
    "Project Manager",
    "Operations Lead",
    "Customer Success Manager",
    "Commercial Director",
    "Marketing Specialist",
    "Product Manager",
    "Revenue Operations Manager",
]

OUTPUT_FILE = "leads_500k_hackathon_clean.csv"

# ----------------------------
# Helpers
# ----------------------------
def build_sources(country: str) -> list[str]:
    return BASE_SOURCES


def maybe_blank(value: str, probability: float) -> str:
    return "" if random.random() < probability else value


def build_email(first_name: str, last_name: str) -> str:
    if first_name and last_name:
        safe_first = "".join(ch for ch in first_name.lower() if ch.isalnum())
        safe_last = "".join(ch for ch in last_name.lower() if ch.isalnum())
        return f"{safe_first}.{safe_last}{random.randint(10, 9999)}@{fake.free_email_domain()}"
    return fake.email()


def random_datetime_within_day(day: datetime) -> datetime:
    return datetime.combine(day.date(), time.min) + timedelta(seconds=random.randint(0, 86399))


def day_multiplier(day: datetime, source: str) -> float:
    weekday = day.weekday()

    if source == "event_import":
        weekday_factors = [0.68, 0.80, 1.00, 1.12, 1.24, 0.60, 0.42]
    elif source == "partner_api":
        weekday_factors = [1.03, 1.06, 1.02, 1.00, 0.97, 0.74, 0.70]
    elif "LinkedinForm_2026" in source or "FacebookForm_2026" in source:
        weekday_factors = [0.96, 1.00, 1.03, 1.03, 0.98, 0.72, 0.66]
    else:
        weekday_factors = [1.00, 1.01, 1.01, 1.00, 0.99, 0.78, 0.74]

    # Minimal noise to keep normal sources well above 50% baseline threshold
    seasonal_noise = random.uniform(0.985, 1.015)
    return weekday_factors[weekday] * seasonal_noise


def base_daily_mean(country: str, source: str) -> float:
    if country == "FR" and source == "LinkedinForm_2026":
        return 160.0
    
    if country == "GB" and source == "web_form":
        return 130.0

    if country == "DE" and source == "web_form":
        return 130.0

    return 30.0 * COUNTRY_WEIGHTS[country] * SOURCE_WEIGHTS[source]


def sample_count(mean_value: float) -> int:
    std_dev = max(1.0, mean_value ** 0.5)
    return max(0, int(round(random.gauss(mean_value, std_dev))))


def make_row(lead_id: int, country: str, source: str, created_dt: datetime) -> list:
    first_name = maybe_blank(fake.first_name(), 0.015)
    last_name = maybe_blank(fake.last_name(), 0.010)
    email = build_email(first_name, last_name)
    title = maybe_blank(random.choice(GENERIC_TITLES), 0.03)
    company = maybe_blank(fake.company(), 0.015)

    return [
        lead_id,
        first_name,
        last_name,
        email,
        title,
        company,
        country,
        source,
        created_dt,
    ]


def recent_group_adjustment(country: str, source: str, day: datetime) -> float:
    if day < RECENT_WINDOW_START:
        return 1.0

    if country == "FR" and source == "LinkedinForm_2026":
        return 0.0

    if source == "web_form" and country in {"GB", "DE"}:
        return 0.15

    # Everyone else remains healthy (100% of baseline on average)
    return 1.0


def is_protected_group(country: str, source: str) -> bool:
    if country == "FR" and source == "LinkedinForm_2026":
        return True
    if source == "web_form" and country in {"DE", "GB"}:
        return True
    return False


# ----------------------------
# 1. Build daily volume plan
# ----------------------------
volume_plan: list[tuple[datetime, str, str, int]] = []
current_day = START_DATE

while current_day <= NOW:
    for country in COUNTRIES:
        for source in build_sources(country):
            baseline = base_daily_mean(country, source)
            baseline *= day_multiplier(current_day, source)
            baseline *= recent_group_adjustment(country, source, current_day)
            
            daily_count = sample_count(baseline)

            # Hard override last 3 days to exactly 0 for FR LinkedinForm_2026
            if country == "FR" and source == "LinkedinForm_2026":
                if current_day >= NOW - timedelta(days=3):
                    daily_count = 0

            volume_plan.append((current_day, country, source, daily_count))

    current_day += timedelta(days=1)


# ----------------------------
# 2. Materialize rows
# ----------------------------
data: list[list] = []
lead_id = 1

for day, country, source, daily_count in volume_plan:
    for _ in range(daily_count):
        created_dt = random_datetime_within_day(day)
        if created_dt > NOW:
            created_dt = NOW - timedelta(seconds=random.randint(0, 60))
        data.append(make_row(lead_id, country, source, created_dt))
        lead_id += 1

# ----------------------------
# 3. Normalize total row count
# Keep the shaped groups intact.
# Spread any backfill across the full timeline for non-shaped groups only.
# ----------------------------
if len(data) > TOTAL_ROWS:
    protected_rows = [row for row in data if is_protected_group(row[6], row[7])]
    other_rows = [row for row in data if not is_protected_group(row[6], row[7])]
    keep_other_count = TOTAL_ROWS - len(protected_rows)

    if keep_other_count < 0:
        raise ValueError("Protected groups alone exceed TOTAL_ROWS. Lower the base volume.")

    data = protected_rows + random.sample(other_rows, keep_other_count)

elif len(data) < TOTAL_ROWS:
    rows_to_add = TOTAL_ROWS - len(data)
    healthy_pool = [
        (country, source)
        for country in COUNTRIES
        for source in build_sources(country)
        if not is_protected_group(country, source)
    ]

    for _ in range(rows_to_add):
        country, source = random.choice(healthy_pool)
        created_dt = fake.date_time_between(start_date=START_DATE, end_date=NOW)
        data.append(make_row(lead_id, country, source, created_dt))
        lead_id += 1

random.shuffle(data)

# ----------------------------
# 4. DataFrame + summary checks
# ----------------------------
df = pd.DataFrame(
    data,
    columns=[
        "lead_id",
        "first_name",
        "last_name",
        "email",
        "title",
        "company",
        "country_code",
        "source",
        "created_date",
    ],
)

created_ts = pd.to_datetime(df["created_date"])


def summarize_group(country: str, source: str) -> dict:
    mask = (df["country_code"] == country) & (df["source"] == source)
    hist_mask = mask & (created_ts < RECENT_WINDOW_START)
    recent_mask = mask & (created_ts >= RECENT_WINDOW_START)
    last_3d_mask = mask & (created_ts >= NOW - timedelta(days=3))

    hist_days = max((RECENT_WINDOW_START.date() - START_DATE.date()).days, 1)
    recent_days = RECENT_WINDOW_DAYS
    hist_avg = hist_mask.sum() / hist_days
    recent_avg = recent_mask.sum() / recent_days
    recent_vs_hist_pct = (recent_avg / hist_avg * 100) if hist_avg else None

    return {
        "historical_rows": int(hist_mask.sum()),
        "recent_rows": int(recent_mask.sum()),
        "last_3d_rows": int(last_3d_mask.sum()),
        "hist_avg": hist_avg,
        "recent_avg": recent_avg,
        "recent_vs_hist_pct": recent_vs_hist_pct,
    }


print("Dataset generation complete")
print("Rows:", len(df))
print()

targets = [
    ("FR", "LinkedinForm_2026", "Isolated source drop"),
    ("GB", "web_form", "Broader web_form weakness (GB)"),
    ("DE", "web_form", "Broader web_form weakness (DE)")
]

for c, s, label in targets:
    summary = summarize_group(c, s)
    if summary['hist_avg'] is not None and summary['recent_avg'] is not None:
        print(f"{label}: {c} | {s}")
        print(f"Historical avg daily: {summary['hist_avg']:.2f}")
        print(f"Recent avg daily:     {summary['recent_avg']:.2f}")
        print(f"Rows in last 3 days:  {summary['last_3d_rows']}")
        print(f"Estimated daily drop: {summary['hist_avg'] - summary['recent_avg']:.2f} rows")
        if summary['recent_vs_hist_pct'] is not None:
             print(f"Recent vs historical: {summary['recent_vs_hist_pct']:.2f}%")
             
    print()

df["created_date"] = pd.to_datetime(df["created_date"]).dt.strftime("%Y-%m-%d %H:%M:%S")
df.to_csv(OUTPUT_FILE, index=False)
print()
print(f"Saved to {OUTPUT_FILE}")

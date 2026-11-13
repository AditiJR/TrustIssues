"""Coded refund limits. Integers in cents. Never read from config, env, policy text or requests."""
from typing import Final

PER_TXN_LIMIT_CENTS: Final = 10_000        # $100.00 per refund
WEEKLY_LIMIT_CENTS: Final = 50_000         # $500.00 per rolling 7 days, all customers
WINDOW_US: Final = 7 * 24 * 3600 * 1_000_000
MAX_AMOUNT_CENTS: Final = 999_999_999      # parse bound only, not a policy limit
SCOPE_TTL_US: Final = 30 * 60 * 1_000_000  # a case scope stops working 30 minutes after it is issued

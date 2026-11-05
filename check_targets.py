"""Request targets separate from stable database keys/history."""

TARGET_OVERRIDES = {
    "tst-stdo.tdms.sibur.ru/cp/": "tst-stdo.tdms.sibur.ru/cp/component/main",
}


def check_target(site):
    return TARGET_OVERRIDES.get(site, site)

import argparse
import base64
import getpass
import json
import csv
import logging
import os
import re
import time
import urllib.parse
from datetime import date, datetime, timedelta
from html.parser import HTMLParser
from typing import Any, Dict, Tuple, List, Union
import requests
from requests_ntlm2.requests_ntlm2 import HttpNtlmAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__all__ = ["login_to_remedy", "logout_from_remedy"]

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# debug logging
# logger.setLevel(logging.DEBUG)

DEFAULT_FIELDS = [
    "Incident Number",
    "Submit Date",
    "Description",
    "Detailed Decription",
    "Reported Source",
    "Service Type",
    "ServiceCI",
    "Categorization Tier 1",
    "Categorization Tier 2",
    "Categorization Tier 3",
    "KSP_AI_IncType",
    "KSP_AI_Service",
    "KSP_AI_OperCat1",
    "KSP_AI_OperCat2",
    "KSP_AI_OperCat3",
]

DEFAULT_LIMIT = 1000
DEFAULT_TIMEOUT = 5
CACHE_FILE_FMT = (
    "itremedy_data_{date}.json"
)
CACHE_FILE_FMT2 = (
    "itremedy_data_{date}.csv"
)

CACHE_FILE_DATE_RE = r"itremedy_data_(\d{4})-(\d{2})-(\d{2})\.json"
VERIFY = False

env_configs = {
    "stage": {
        "sso_url": "",
        "tenant": "",
        "remedy_url": "",
        "api_url": "",
        "cookie_name": "",
        "goto": "",
    },
    "prod": {
        "sso_url": "",
        "tenant": "",
        "remedy_url": "",
        "api_url": "",
        "cookie_name": "",
        "goto": "",
    },
}


class TokenExtractionParser(HTMLParser):

    def error(self, message):
        pass

    def __init__(self, *_args, **kwargs):
        super().__init__(*_args, **kwargs)
        self._saml_response_name = "SAMLResponse"
        self._relay_state_name = "RelayState"
        self._tokens = dict()

    def handle_starttag(self, tag, attrs):

        if tag == "input":
            attrs = dict(attrs)
            logger.debug("Found an input field while parsing with attrs: %s", attrs)
            if (
                    attrs.get("name") == self._saml_response_name
                    and attrs.get("value") is not None
            ):
                self._tokens[self._saml_response_name] = attrs.get("value")
                logger.debug(
                    "Found SAML response name while parsing: %s", attrs.get("value")
                )
            elif (
                    attrs.get("name") == self._relay_state_name
                    and attrs.get("value") is not None
            ):
                self._tokens[self._relay_state_name] = attrs.get("value")
                logger.debug("Found relay state while parsing: %s", attrs.get("value"))

    def get_tokens(self) -> Dict[str, str]:

        if (
                self._saml_response_name in self._tokens
                and self._relay_state_name in self._tokens
        ):
            return self._tokens
        raise ValueError("The parsed page does not contain necessary tokens")


def _construct_urls(env: str) -> Tuple[str, str]:
    if environment not in env_configs:
        raise ValueError(f"Use one of {', '.join(env_configs.keys())} as environment")
    env_url_parts = env_configs[env]
    sso_url = "{}/rsso/start".format(env_url_parts["sso_url"])
    receiver_url = "{}/rsso/receiver".format(env_url_parts["sso_url"])
    return sso_url, receiver_url


def _get_sso_tokens_and_referer(
        _url: str, _domain: str, _user: str, _password: str, _env: str
) -> Tuple[Dict[str, str], str]:
    ntlm_auth = HttpNtlmAuth(f"{_domain}\\{_user}", _password)
    logger.info("Requesting SAML/relay from %s", _url)
    sso_resp = requests.post(
        _url,
        data={
            "goto": env_configs[_env]["goto"],
            "tenant": env_configs[_env]["tenant"],
            "url_hash_handler": "true",
        },
        auth=ntlm_auth,
        verify=VERIFY,
    )
    logger.info("Got SSO token")
    if not sso_resp.ok:
        logging.error(
            "Error getting SSO token: (%s) %s", sso_resp.status_code, sso_resp.text
        )
    sso_resp.raise_for_status()
    resp = sso_resp.text
    sso_parser = TokenExtractionParser()
    sso_parser.feed(resp)
    return sso_parser.get_tokens(), sso_resp.url


def _extract_token_from_cookie(_req: requests.Response, _env: str):
    cookie_name = env_configs[_env]["cookie_name"]
    if cookie_name in _req.cookies:
        token_base64 = _req.cookies.get(cookie_name)
        token_base64 = token_base64.split(".", 1)[-1]
        token_json = base64.b64decode(token_base64).decode("utf-8")
        token_dict = json.loads(token_json)
        token = token_dict["tokenId"]
        return token
    raise ValueError("Token not found in cookie")


def _get_auth_token_id(
        _receiver_url: str,
        _referer: str,
        _tokens: Dict[str, str],
        _domain: str,
        _username: str,
        _password: str,
        _env: str,
) -> str:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": _referer,
    }
    ntlm_auth = HttpNtlmAuth(f"{_domain}\\{_username}", _password)
    logger.info("Requesting SSO token id from %s", _receiver_url)
    resp = requests.post(
        _receiver_url,
        params=_tokens,
        auth=ntlm_auth,
        headers=headers,
        allow_redirects=False,
        verify=VERIFY,
    )

    if not resp.ok:
        resp.raise_for_status()

    return _extract_token_from_cookie(resp, _env)


def _do_sso_auth(
        _username: str, _password: str, _domain: str = "kl", _env: str = "prod"
) -> str:
    sso_url, receiver_url = _construct_urls(_env)
    tokens, referer = _get_sso_tokens_and_referer(sso_url, _domain, _username, _password, _env)
    token_id = _get_auth_token_id(
        receiver_url, referer, tokens, _domain, _username, _password, _env
    )
    return token_id


def _get_jwt_token(_username: str, _token_id: str, _env: str = "prod") -> str:
    if _env not in env_configs:
        raise ValueError(f"Use one of {', '.join(env_configs.keys())} as environment")
    url = f'{env_configs[_env]["api_url"]}/api/jwt/login'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "username": f"{_username}@avp.ru",
        "authString": _token_id,
    }
    logger.info("Requesting JWT from %s", url)
    resp = requests.post(url, headers=headers, data=params, verify=VERIFY, timeout=60)

    if not resp.ok:
        logging.error("Error getting JWT token: (%s) %s", resp.status_code, resp.text)
        resp.raise_for_status()

    return resp.text


def login_to_remedy(
        _username: str, _password: str, _domain: str = "kl", _env: str = "prod"
) -> str:
    logging.info("Logging in to Remedy")
    sso_token_id = _do_sso_auth(_username, _password, _domain, _env)
    jwt_token = _get_jwt_token(_username, sso_token_id, _env)
    return jwt_token


def logout_from_remedy(_jwt_token: str, _env: str = "prod") -> None:
    if _env not in env_configs:
        raise ValueError(f"Use one of {', '.join(env_configs.keys())} as environment")
    url = env_configs[_env]["api_url"] + "/api/jwt/logout"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"AR-JWT {_jwt_token}"
    }
    logging.info("Logging out of Remedy")
    resp = requests.post(url, headers=headers, verify=VERIFY)

    logger.info("Logged out")

    if not resp.ok:
        logging.error(
            "Error logging out of Remedy: (%s) %s", resp.status_code, resp.text
        )
        resp.raise_for_status()


def _load_page(_url: str, _jwt_token: str) -> Dict:
    logger.info("Loading page from url: %s", _url)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"AR-JWT {_jwt_token}",
        "x-requested-by": "x"
    }

    resp = requests.get(_url, headers=headers, verify=VERIFY)

    if not resp.ok:
        logging.error("Error loading page, %s, %s", resp.status_code, resp.text)
        resp.raise_for_status()

    return resp.json()


def _construct_initial_url(
        _query: str,
        _fields=None,
        _limit: int = DEFAULT_LIMIT,
        _offset: int = 0,
        _env="prod",
) -> str:
    if _fields is None:
        _fields = DEFAULT_FIELDS
    if _env not in env_configs:
        raise ValueError(f"Use one of {', '.join(env_configs.keys())} as environment")
    url = env_configs[_env]["api_url"] + "/api/arsys/v1/entry/HPD:Help Desk"
    params = {
        "q": _query,
        "limit": _limit,
        "offset": _offset,
    }
    encoded_params = urllib.parse.urlencode(params)
    url = f"{url}?{encoded_params}&fields=values({','.join(_fields)})"
    return url


def load_incidents(
        _username: str,
        _password: str,
        _domain: str,
        _query: str,
        _fields=None,
        _limit: int = DEFAULT_LIMIT,
        _offset: int = 0,
        _timeout: Union[int, float] = DEFAULT_TIMEOUT,
        _env="prod",
) -> List[Dict[str, Any]]:
    if _fields is None:
        _fields = DEFAULT_FIELDS
    jwt_token = ""
    url = _construct_initial_url(_query, _fields, _limit, _offset, _env)
    data = list()
    try:
        while True:
            jwt_token = login_to_remedy(_username, _password, _domain, _env)
            page = _load_page(url, jwt_token)
            entries = page.get("entries")
            links = page.get("_links")

            if entries:
                for entry in entries:
                    data.append(entry["values"])

            if links:
                if "next" in links and (links["next"]) and ("href" in links["next"][0]):
                    url = links["next"][0]["href"]
                    logging.info("Found next url: %s", url)
                    logout_from_remedy(jwt_token, _env)
                    time.sleep(_timeout)
                    jwt_token = ""
                    continue

            logging.info("Next url not found, day fetched")
            time.sleep(_timeout)
            break
    except Exception as e:
        if jwt_token:
            logout_from_remedy(jwt_token, _env)
        raise e

    if jwt_token:
        logout_from_remedy(jwt_token, _env)
    return data


def load_incidents_by_date(
        _username: str,
        _password: str,
        _domain: str,
        _epoch_current_date: int,
        _epoch_end_date: int,
        _fields=None,
        _limit: int = DEFAULT_LIMIT,
        _offset: int = 0,
        _env="prod",
) -> List[Dict[str, Any]]:
    if _fields is None:
        _fields = DEFAULT_FIELDS
    query_pattern = "'Submit Date' >= \"{start}\" AND 'Submit Date' < \"{end}\""
    _query = query_pattern.format(
        start=_epoch_current_date, end=_epoch_end_date

    )
    return load_incidents(
        _username=_username,
        _password=_password,
        _domain=_domain,
        _query=_query,
        _fields=_fields,
        _limit=_limit,
        _offset=_offset,
        _env=_env,
    )


def load_and_save_data(
        _username: str,
        _password: str,
        _domain: str,
        _start_date: date,
        _end_date: date,
        _epoch_start_date: int,
        _results_path: str,
        _overwrite_cache: bool = False,
        _fields=None,
        _limit: int = DEFAULT_LIMIT,
        _offset: int = 0,
        _env="prod",
):
    if _fields is None:
        _fields = DEFAULT_FIELDS
    os.makedirs(_results_path, exist_ok=True)

    step = timedelta(days=1)
    epoch_step = 86400
    current_date = _start_date
    next_date = current_date + step
    _epoch_current_date = _epoch_start_date
    _epoch_next_date = _epoch_current_date + epoch_step
    if not _overwrite_cache:
        cache_contents = os.listdir(_results_path)
        logging.debug("Cache contents: %s", cache_contents)
        cached_dates: List[Any] = [
            re.match(CACHE_FILE_DATE_RE, fname) for fname in cache_contents
        ]
        logging.debug("Cached dates (pre-proc): %s", cached_dates)
        cached_dates = [
            date(int(match[1]), int(match[2]), int(match[3]))
            for match in cached_dates
            if match
        ]
        logging.debug("Cache dates (post-proc): %s", cached_dates)
    else:
        cached_dates = []
    while current_date < _end_date:
        logging.debug("Current date for fetching is: %s", [current_date])
        if not _overwrite_cache and current_date in cached_dates:
            logging.info("This date (%s) data has already been fetched", current_date)
        else:
            logging.info("Fetching date from %s to %s", current_date, next_date)
            data = load_incidents_by_date(
                _username=_username,
                _password=_password,
                _domain=_domain,
                _epoch_current_date=_epoch_current_date,
                _epoch_end_date=_epoch_next_date,
                _fields=_fields,
                _limit=_limit,
                _offset=_offset,
                _env=_env,
            )
            date_str = current_date.strftime("%Y-%m-%d")
            file_name = CACHE_FILE_FMT.format(date=date_str)
            file_name2 = CACHE_FILE_FMT2.format(date=date_str)
            logging.info("Saving data for %s to %s", current_date, file_name)
            with open(os.path.join(_results_path, file_name), "w", encoding="utf-8") as file_out:
                json.dump(data, file_out)
            logging.info("Saving data for %s to %s", current_date, file_name2)
            with open(os.path.join(_results_path, file_name)) as json_file:
                jsondata = json.load(json_file)
                data_file = open(os.path.join(_results_path, file_name2), 'w', encoding="utf-8", newline='')
                csv_writer = csv.writer(data_file)
                count = 0
                count2 = 0
                for data in jsondata:
                    if count == 0:
                        header = data.keys()
                        csv_writer.writerow(header)
                        count += 1
                    csv_writer.writerow(data.values())
                    count2 += 1
                logging.info("Writed %s incidents", count2)
                data_file.close()

        current_date += step
        next_date += step
        _epoch_current_date += epoch_step
        _epoch_next_date += epoch_step

    logging.info("Fetching complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IT Remedy (BMC Remedy) authentication and data fetching"
    )
    parser.add_argument("data_path", help="The folder to save data to")
    parser.add_argument(
        "start_date", help="First date for data to be fetched (inclusive) as YYYY-mm-dd"
    )
    parser.add_argument("username", help="Username for SSO")
    parser.add_argument(
        "--domain", default="kl", help="Domain of the provided username"
    )
    parser.add_argument(
        "--end_date", help="Last date for data to be fetched (exclusive) as YYYY-mm-dd"
    )
    parser.add_argument(
        "--env", default="prod", help="Environment: either `prod` or `stage`"
    )
    parser.add_argument("--overwrite_cache", action="store_true", default=False)

    logging.basicConfig(level=logging.INFO)

    args = parser.parse_args()
    username = args.username
    domain = args.domain
    environment = args.env
    if environment not in {"prod", "stage"}:
        logging.critical("Please, use either `prod` or `stage` for --env")
        quit()

    password = getpass.getpass(f"Password for {args.domain}\\{args.username}: ")
    start_date = datetime.strptime(args.start_date, "%Y-%m-%d %H:%M:%S").date()
    epoch_start_date = round(datetime.strptime(args.start_date, "%Y-%m-%d %H:%M:%S").timestamp())
    if args.end_date:
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()
        epoch_end_date = round(datetime.strptime(args.end_date, "%Y-%m-%d %H:%M:%S").timestamp())
    else:
        end_date = date.today()
        epoch_end_date = round(datetime.strptime(str(date.today()), "%Y-%m-%d").timestamp())

    load_and_save_data(
        _username=username,
        _password=password,
        _domain=domain,
        _start_date=start_date,
        _end_date=end_date,
        _epoch_start_date=epoch_start_date,
        _results_path=args.data_path,
        _overwrite_cache=args.overwrite_cache,
        _env=environment,
    )
    logging.info("Done.")

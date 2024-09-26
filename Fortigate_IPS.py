#!/usr/bin/python3
import sys
sys.path.append('/app/customwd')
import re
import json
import na_utils
import os
import logging
import logging.handlers
import urllib.request
import urllib.parse
import ssl

def refine_context(ctx, msg, exec_id, logger):

    reason = user = srcip = dstip = action = ref = None

    try:
        logid, srcip, dstip = re.findall(r'logid=\"(.*?)\" .*srcip=(.*?) .*dstip=(.*?)\ ', msg)[0]
        user = re.findall(r'user="(.*?)"', msg)[0]
        reason = re.findall(r'attack=\"(.*?)\"', msg)[0]
        action = re.findall(r'action="(.*?)"', msg)[0]
        #ref = re.findall(r'ref="(.*?)"', msg)[0]
    except IndexError as exception:
        logger.info("{0} - refine_context Exception: {1}".format(exec_id, exception))
        exit(0)

    except Exception as exception:
        logger.info("{0} - refine_context Exception: {1}".format(exec_id, exception))
        exit(0)

    return {
        'logid': logid,
        'srcip': srcip,
        'dstip': dstip,
        'action': action,
        'reason': reason,
        #'ref': ref,
        'user': user
        }

def ban_client_by_ip(exec_id, ctx, logger):
    ovserver = "127.0.0.1"
    ovport = 514
    with open('/app/CustomRules/{}/omnivista/omnivista.json'.format(ctx["ano_ref"])) as json_file:
        ovdata = json.load(json_file)
        ovserver = ovdata['server']
        ovport = ovdata['port']

    log_to_ov = logging.getLogger('log_to_ov')
    log_to_ov.setLevel(logging.DEBUG)
    handler = logging.handlers.SysLogHandler(address = (ovserver,ovport))
    log_to_ov.addHandler(handler)

    log_to_ov.debug('app=NwkAdvisor_Quarantine,src=' + ctx["srcip"])
    logger.info("{0} - ban_client_by_ip - syslog message sent to OV {1}:{2}".format(exec_id, ovdata['server'], ovdata['port']))
    return ovserver

def get_config():
    # Get environment variables
    backend_key = os.getenv("BACKEND_API_KEY")
    base_url = os.getenv("BASE_URL")

    if not base_url:
        base_url = "http://na-backend.ale-ovna.svc.cluster.local:1337/internal/"
    if not backend_key:
        backend_key = "ThisIsMyApiKey"

    # Set default values and timeout
    timeout = 10  # 10 seconds timeout
    default_headers = {
        "Content-Type": "application/json",
        "x-api-key": backend_key
    }

    # Return configuration as a dictionary
    return {
        "base_url": base_url,
        "timeout": timeout,
        "default_headers": default_headers
    }

def extract_cookies(headers):
    cookies = []

    # Iterate through the headers
    for key, value in headers:
        if key.lower() == 'set-cookie':  # Check for 'Set-Cookie' header (case insensitive)
            # Split by ';' and take the first part (the cookie name=value)
            cookie_value = value.split(';')[0]
            cookies.append(cookie_value)
            # Stop if we already have 3 cookies
            if len(cookies) == 3:
                break

    str_cookies = "; ".join(cookies)
    return str_cookies

def send_request(method, url, headers, payload=None, file=None, timeout=500, verify=True):
    try:
        if payload:
            if headers.get('Content-Type') == 'application/json':
                data = json.dumps(payload).encode('utf-8')  # JSON payload
            else:
                data = urllib.parse.urlencode(payload).encode('utf-8')  # Form data
        else:
            data = None

        if file:
            raise NotImplementedError("File upload using urllib is more complex and not directly supported.")

        req = urllib.request.Request(url, data=data, method=method.upper())

        for key, value in headers.items():
            req.add_header(key, value)

        if verify:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = response.read().decode('utf-8')
                response_cookies = extract_cookies(response.getheaders())
                response_headers = dict(response.getheaders())
                return {"status_code": response.status, "text": result, "cookies": response_cookies, "headers": response_headers}
        else:
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
                result = response.read().decode('utf-8')
                response_cookies = extract_cookies(response.getheaders())
                response_headers = dict(response.getheaders())
                return {"status_code": response.status, "text": result, "cookies": response_cookies, "headers": response_headers}

    except urllib.error.HTTPError as e:
        print(f"HTTP error: {e.code}, {e.reason}")
    except urllib.error.URLError as e:
        print(f"URL error: {e.reason}")
    except Exception as exception:
        print("Error sending request: " + str(exception))

def ban_stellar_wifi_client(exec_id, ctx, logger):
    # Modify according to your needs
    # OmniVista 2500 is often deployed with a self-signed certified. Use False in that case, otherwise True.
    verify_certs = False

    with open('/app/CustomRules/{}/omnivista/omnivista.json'.format(ctx["ano_ref"])) as json_file:
        ovdata = json.load(json_file)
        ovserver = ovdata['server']
        username = ovdata['username']
        password = ovdata['password']

    # Login to OmniVista API
    ov_header = {
        "Content-Type":"application/json"
    }

    ov_login_data = {
        "userName":username,
        "password":password
    }
    timeout=60

    ov_login = send_request("POST", f"https://{ovserver}/api/login", headers=ov_header, payload=ov_login_data, timeout=timeout,verify=verify_certs)
    #print(str(ov_login["status_code"]), ov_login["Cookie"], ov_login["text"], "OV Login")
    logger.info("{0} - OV Login status: {1}".format(exec_id, ov_login["status_code"]))

    ov_header["Cookie"] = ov_login["cookies"]

    client_query = {
        "pageNumber":1,
        "pageSize":1000,
        "orderBy":"clientName",
        "orderType":"ASC"
    }

    # Get the initial 1000 clients connected to Stellar Wireless
    stellar_clients = send_request("POST", f"https://{ovserver}/api/wma/onlineClient/getOnlineClientListByPage", headers=ov_header, payload=client_query, timeout=timeout, verify=verify_certs)
    #print(stellar_clients["status_code"], stellar_clients["text"], "OV Get Stellar Clients")
    stellar_clients_json = json.loads(stellar_clients["text"])

    #print("This network has {} Stellar Wireless clients".format(stellar_clients_json["data"]["totalRecords"]))
    logger.info("{0} - This network has  {1} Stellar Wireless clients associated".format(exec_id, stellar_clients_json["data"]["totalRecords"]))
    #print(f"Attempting to find client {srcip} to add it to Blocklist")

    clientMac = ""
    connectedAP = ""

    for client in stellar_clients_json['data']['data']:
        if client['clientIP'] == ctx["srcip"]:
            clientMac = client['clientMac']
            connectedAP = client['apName']
            logger.info("{0} - ban_stellar_wifi_client - WLAN Client MAC Address: {1} - WLAN Stellar AP Name: {2}".format(exec_id, clientMac, connectedAP))
            break

    # If clientMac wasn't found via the first page (1000 clients), attempt through following pages (if more than 1)
    if (clientMac == "" and stellar_clients_json['data']['numberOfPages'] > 1):
        page = 2
        while page <= stellar_clients_json['data']['numberOfPages']:
            client_query = {
                "pageNumber":page,
                "pageSize":1000,
                "orderBy":"clientName",
                "orderType":"ASC"
            }
            stellar_client_np = send_request("POST", f"https://{ovserver}/api/wma/onlineClient/getOnlineClientListByPage", headers=ov_header, payload=client_query, timeout=timeout, verify=verify_certs)
            stellar_client_np_json = (json.loads(stellar_client_np["text"]))
            for client in stellar_client_np_json['data']['data']:
                if client['clientIP'] == ctx["srcip"]:
                    clientMac = client['clientMac']
                    connectedAP = client['apName']
                    logger.info("{0} - ban_stellar_wifi_client - WLAN Client MAC Address: {1} - WLAN Stellar AP Name: {2}".format(exec_id, clientMac, connectedAP))
                    break
            # Make sure we also break the while loop
            if clientMac != "":
                break
            page += 1

    if clientMac == "":
        # Return early, as we didn't find a Wi-Fi client
        ov_logout = send_request("GET", f"https://{ovserver}/api/logout", headers=ov_header, timeout=timeout, verify=verify_certs)
        #print(ov_logout["status_code"], ov_logout["text"], "OV Logout")
        return False

    # Add client to Blocklist, make sure reason doesn't exceed 100 characters
    blocklist_entry = {
        "memList":[clientMac],
        "method":"add",
        "agingTime":None,
        "reason":"OmniVista Network Advisor secured your network from {} on AP {connectedAP}"[:100].format(ctx["srcip"])
    }
    add_to_blocklist = send_request("POST", f"https://{ovserver}/api/wma/wips/clientList/edit", headers=ov_header, payload=blocklist_entry, timeout=timeout, verify=verify_certs)
    #print(add_to_blocklist["status_code"], add_to_blocklist["reason"], "OV Add Client to Blocklist")
    logger.info("{0} - Client {1} is added into the OmniVista BlockList".format(exec_id, clientMac, add_to_blocklist["status_code"]))
    # Logout from OmniVista API
    ov_logout = send_request("GET", f"https://{ovserver}/api/logout", headers=ov_header, timeout=timeout, verify=verify_certs)
    #print(ov_logout.status_code, ov_logout.reason, "OV Logout")

def send_notification(body,logger):
    # Send notification to the backend
    cfg = get_config()
    headers = cfg.get("default_headers")
    timeout = cfg.get("timeout")
    url = cfg.get("base_url") + "notification"

    #logger.info(f"Sending request on URL:{url}")
    #logger.info(f"Header: {headers}")
    #logger.info(f"Body: {body}")
    #logger.info(f"Timeout: {timeout}")

    answer = send_request("POST", url, headers=headers, payload=body, timeout=timeout)
    #logger.info(f"Answer: {}".format(answer["text"]))


# ----------------------------------------------------------#
# Temporary functions for sending log to notifications
ADAPTIVE_CARDS_BASE_PATH = "/app/adaptive_cards"

def send_logs(data, exec_id, watchdog_name, anoId, bubblesIds, logger):
    payload = {}
    payload["bubblesIds"] = bubblesIds.split(",")

    # Load adaptive data from a file
    adaptive_path = os.path.join(ADAPTIVE_CARDS_BASE_PATH, 'adaptivecard_log.json')
    with open(adaptive_path, 'r') as file:
        adaptive = json.load(file)

    # Extract values from data (with default values)
    adaptive_data = {
        "execId": exec_id,
        "anoId": anoId,
        "watchdogName": watchdog_name,
        "defChoice": data.get("defChoice", ""),
        "ignore": data.get("ignore", ""),
        "disable": data.get("disable", ""),
        "altChoice": data.get("altChoice", ""),
        "action": data.get("action", ""),
        "remember": data.get("remember", ""),
        "url1": data.get("url1", ""),
        "action_url1": data.get("action1", ""),
        "url2": data.get("url2", ""),
        "action_url2": data.get("action2", ""),
        "urlText": data.get("urlText", ""),
        "txt1": data.get("anoText", ""),
        "txt2": data.get("detText", ""),
        "txt3": data.get("recText", ""),
        "txt4": data.get("txt4", "")
    }

    adaptive["$data"] = adaptive_data
    payload["adaptiveCard"] = adaptive
    payload["message"] = data.get("anoText", "")

    logger.info("{} - Sending payload to backend".format(exec_id))
    logger.info(json.dumps(payload))

    # Send Notification (replace with actual logic)
    try:
        send_notification(payload,logger)
    except Exception as err:
        raise Exception(f"Error sending notification: {err}")

def notify_more_logs(ctx, ovserver, exec_id, logger):
    payload = {}

    logger.info("{} - Sending remediation result".format(exec_id))

    payload['anoText'] = ctx['notify_more']['more_logs_{}'.format(ctx["accomplished"])].format(ctx['srcip'])
    payload['detText'] = ctx['notify_more']['more_logs_det'].format(ctx['logid'],ctx['srcip'],ctx['dstip'])
    payload['action1'] = ctx['notify_more']['log_access']
    payload['recText'] = ctx['notify_more']['more_logs_rec']
    payload['url1'] = "http://{}/#/quarantineManager/banned".format(ovserver)

    #logger.info(json.dumps(ctx))
    logger.info(json.dumps(payload))

    send_logs(payload, exec_id, ctx['ano_ref'], "", ctx["bubbles_ids"],logger)


def set_context(ano_ctx, msg, ano_id, exec_id, logger):
    logger.info("anomaly watchdog set context started")
    ctx = json.loads(ano_ctx)
    ctx.update(refine_context(ctx,msg,exec_id,logger))

    is_exist = na_utils.is_key_exist_in_redis(ano_id, ano_ctx, ["pattern_ctx", "ipAddress"])
    if is_exist.err != None :
        logger.error("An error occurred: is_key_exist_in_redis\n")
        exit(1)

    if is_exist.exist :
        ctx['early_termination'] = "repeated ano"
        logger.info("anomaly watchdog set context exited")
        print(json.dumps(ctx))
        exit(0)

    logger.info(json.dumps(ctx))

    logger.info("before ctx things")
    ctx['anoText'] = ctx['anoText'].format(ctx['host'],ctx['ipAddress'])
    ctx['details'] = ctx['details'].format(ctx['logid'], ctx['srcip'], ctx['dstip'], ctx['user'], ctx['action'], ctx['reason'])
    #ctx['kbUrl'] = ctx['ref']
    ctx['recorded_details'] = ctx['details']
    logger.info("after ctx things")

    logger.info("anomaly watchdog set context exited")
    print(json.dumps(ctx))

def remediation(selected_decision, exec_id, ano_ctx, cld, logger):
    logger.info("start remediation - execId: {}".format(exec_id))

    ctx = json.loads(ano_ctx)
    common_lang_data = json.loads(cld)
    dec = ""

    logger.info(json.dumps(ctx))
    logger.info(json.dumps(common_lang_data))

    if selected_decision == "DEC_MONITORING":
            dec = common_lang_data['decision_monitoring']

    if selected_decision == "DEC_TIMEOUT":
        if na_utils.can_apply_rec_remed_on_timeout():
            selected_decision = "DEC_RECOMMENDED"
        else:
            dec = common_lang_data['decision_timeout']

    if selected_decision == "DEC_RECOMMENDED":
        logger.info("{} - Remediate DEC_RECOMMENDED".format(exec_id))
        # TODO:
        # Create a QMR rule in OV2500
        # Send a syslog to OV2500 QMR to quarantine the device
        #
        # If the client is not found in Wi-Fi clients, process via OV QMR
        ovserver = ban_stellar_wifi_client(exec_id,ctx,logger)
        # ovserver is either set
        # ... then client is a Wi-Fi client
        # ... or False, then go through QMR
        if not ovserver:
            ovserver = ban_client_by_ip(exec_id,ctx,logger)
            ctx["accomplished"] = "qmr"
        else:
            ctx["accomplished"] = "blocklist"
        dec = "Blocked"
        det = notify_more_logs(ctx,ovserver,exec_id,logger)

    if selected_decision == "DEC_IGNORE":
        logger.info("{} - Remediate DEC_IGNORE".format(exec_id))
        dec = common_lang_data['decision_ignore']

    # Keep this print to record the decision
    print(dec)

""" main """
def main():
    match sys.argv[1]:
        case "set_context":
            logger = na_utils.init_new_logger(sys.argv[6])
            # arg 2: ano context
            # arg 3: msg
            # arg 4: anoId
            # arg 5: execId
            # arg 6: watchdog name
            set_context(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], logger)
        case "remediation":
            logger = na_utils.init_new_logger(sys.argv[6])
            # arg 2: selected decision
            # arg 3: execId
            # arg 4: ano context
            # arg 5: common lang data
            remediation(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], logger)
        case _:
            print("invalid arg")

if __name__ == "__main__":
    main()

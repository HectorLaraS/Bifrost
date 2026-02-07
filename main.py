import os
import logging
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple

import requests
from dotenv import load_dotenv

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
)

try:
    from pysnmp.hlapi.asyncio import sendNotification as send_notification_func
except ImportError:
    from pysnmp.hlapi.asyncio import send_notification as send_notification_func


# ==========================
# 🔧 ENV
# ==========================
load_dotenv()

API_URL = os.getenv("API_URL")
API_USER = os.getenv("API_USER")
API_PASS = os.getenv("API_PASS")

TRAP_RECEIVER_IP = os.getenv("TRAP_RECEIVER_IP")
TRAP_RECEIVER_PORT = int(os.getenv("TRAP_RECEIVER_PORT", "1162"))
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")

ENTERPRISE_TRAP_OID = os.getenv("ENTERPRISE_TRAP_OID", "1.3.6.1.4.1.11307.10")
DEFAULT_LOCATION = os.getenv("DEFAULT_LOCATION", "unknown")

TIMEOUT_SECONDS = 5

# ==========================
# 📝 LOGGING
# ==========================
# ERROR log
logging.basicConfig(
    filename="bifrost_errors.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
error_logger = logging.getLogger("BIFROST_ERROR")

# EXECUTION log (nuevo)
exec_logger = logging.getLogger("BIFROST_EXEC")
exec_logger.setLevel(logging.INFO)

exec_handler = logging.FileHandler("bifrost_execution.log")
exec_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
exec_logger.addHandler(exec_handler)


class BifrostAPIError(Exception):
    pass


# ==========================
# 🌐 CONSUMIR API
# ==========================
def obtener_nodos() -> List[Dict[str, Any]]:
    try:
        r = requests.get(
            API_URL,
            auth=(API_USER, API_PASS),
            timeout=TIMEOUT_SECONDS,
        )

        if r.status_code == 401:
            raise BifrostAPIError("Credenciales inválidas (401)")
        if r.status_code != 200:
            raise BifrostAPIError(f"Respuesta inesperada: {r.status_code}")

        data = r.json()
        if not isinstance(data, list):
            raise BifrostAPIError("El payload no es una lista")

        return data

    except Exception as e:
        error_logger.error(f"Error al obtener nodos: {e}", exc_info=True)
        raise


# ==========================
# 🧱 UTIL
# ==========================
def ip_mock_por_nodeid(node_id: int) -> str:
    a = (node_id // 256) % 256
    b = node_id % 256
    return f"10.199.{a}.{b}"


def construir_varbinds(
    nodo: Dict[str, Any]
) -> List[Tuple[ObjectIdentity, OctetString]]:
    node_id = int(nodo.get("NodeID"))
    caption = str(nodo.get("Caption", f"node-{node_id}"))
    status = str(nodo.get("Status", "unknown")).lower()
    vendor = str(nodo.get("Vendor", "unknown"))
    node_ip = nodo.get("NodeIP") or ip_mock_por_nodeid(node_id)
    location = str(nodo.get("location") or DEFAULT_LOCATION)

    SYSUPTIME_OID   = "1.3.6.1.2.1.1.3.0"
    SNMP_TRAP_OID   = "1.3.6.1.6.3.1.1.4.1.0"
    GENERIC_OID     = "1.3.6.1.6.3.1.1.4.3.0"
    SYSLOCATION_OID = "1.3.6.1.2.1.1.6.0"

    STATUS_OID  = f"{ENTERPRISE_TRAP_OID}.1"
    CAPTION_OID = f"{ENTERPRISE_TRAP_OID}.2"
    NODE_IP_OID = f"{ENTERPRISE_TRAP_OID}.3"
    NODE_ID_OID = f"{ENTERPRISE_TRAP_OID}.4"
    VENDOR_OID  = f"{ENTERPRISE_TRAP_OID}.5"

    return [
        (ObjectIdentity(SYSUPTIME_OID),   OctetString("0")),
        (ObjectIdentity(SNMP_TRAP_OID),   OctetString(ENTERPRISE_TRAP_OID)),
        (ObjectIdentity(GENERIC_OID),     OctetString("1.3.6.1.4.1.11307")),
        (ObjectIdentity(SYSLOCATION_OID), OctetString(location)),
        (ObjectIdentity(STATUS_OID),      OctetString(status)),
        (ObjectIdentity(CAPTION_OID),     OctetString(caption)),
        (ObjectIdentity(NODE_IP_OID),     OctetString(node_ip)),
        (ObjectIdentity(NODE_ID_OID),     OctetString(str(node_id))),
        (ObjectIdentity(VENDOR_OID),      OctetString(vendor)),
    ]


# ==========================
# 📡 ENVIAR TRAP
# ==========================
async def enviar_trap(varbinds, target):
    target = await UdpTransportTarget.create(
        (target, TRAP_RECEIVER_PORT)
    )

    res = await send_notification_func(
        SnmpEngine(),
        CommunityData(SNMP_COMMUNITY, mpModel=1),
        target,
        ContextData(),
        "trap",
        NotificationType(ObjectIdentity(ENTERPRISE_TRAP_OID))
        .add_varbinds(*varbinds),
    )

    if isinstance(res, tuple) and len(res) == 4:
        error_indication, error_status, error_index, _ = res
    else:
        error_indication, error_status, error_index = res, 0, 0

    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(
            f"{error_status.prettyPrint()} at {error_index}"
        )


# ==========================
# 🚀 MAIN
# ==========================
async def main():
    # 1️⃣ Marca hora de obtención de API
    api_fetch_time = datetime.now()

    t_fetch_start = time.perf_counter()
    nodos = obtener_nodos()
    t_fetch_end = time.perf_counter()

    exec_logger.info(
        f"API fetch at {api_fetch_time.isoformat()} | "
        f"nodes={len(nodos)} | "
        f"fetch_time={(t_fetch_end - t_fetch_start):.3f}s"
    )

    # 2️⃣ Medir envío de traps
    t_trap_start = time.perf_counter()

    for nodo in nodos:  # quita [:5] cuando quieras
        vb = construir_varbinds(nodo)
        await enviar_trap(vb,TRAP_RECEIVER_IP)
        await asyncio.sleep(0.02)

    t_trap_end = time.perf_counter()

    exec_logger.info(
        f"Trap send completed | "
        f"nodes_sent={len(nodos)} | "
        f"send_time={(t_trap_end - t_trap_start):.3f}s"
    )

    print("✅ Ejecución completada correctamente")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        error_logger.error(
            f"Fallo en BIFROST sender: {e}", exc_info=True
        )
        print(f"❌ Error: {e}")

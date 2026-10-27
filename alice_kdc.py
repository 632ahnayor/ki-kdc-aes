"""
alice_kdc.py: Sisi Alice untuk langkah 1-2 key distribution.

(1) Alice -> KDC : IDA, IDB, N1
(2) KDC -> Alice : E(Ka, [Ks || IDA || IDB || N1]), E(Kb, [Ks || IDA])
"""

import socket

import aes
import common


class GagalKDC(Exception):
    """Dilempar jika permintaan session key ke KDC gagal."""


def minta_session_key(alamat_kdc, ida, idb, ka):
    """Minta Ks dan tiket Bob melalui langkah (1)-(2)."""
    masalah = common.cek_id(ida) or common.cek_id(idb)
    if masalah:
        raise GagalKDC(masalah)
    masalah = common.cek_key(ka)
    if masalah:
        raise GagalKDC(masalah)

    n1 = common.buat_nonce()
    sock = None
    try:
        sock = socket.create_connection(alamat_kdc, timeout=10)
        sock.settimeout(10)
        penerima = common.Penerima(sock)

        common.kirim(sock, {"step": 1, "ida": ida, "idb": idb, "n1": n1})
        common.log(ida, f"Langkah (1): kirim IDA={ida}, IDB={idb}, N1={n1} ke KDC")

        pesan = penerima.terima()
        if pesan is None:
            raise GagalKDC("KDC menutup koneksi tanpa memberi balasan")
        if pesan.get("step") != 2:
            raise GagalKDC(pesan.get("error", "Balasan KDC bukan langkah (2)"))
        if "data" not in pesan or "ticket" not in pesan:
            raise GagalKDC("Balasan KDC tidak berisi data dan tiket")
        if not isinstance(pesan["data"], str) or not isinstance(pesan["ticket"], str):
            raise GagalKDC("Format data atau tiket dari KDC tidak valid")

        common.log(ida, "Langkah (2): terima balasan KDC")
        common.log(ida, f"  data (hex)  : {pesan['data']}")
        common.log(ida, f"  tiket (hex) : {pesan['ticket']}")
        try:
            ks, ida_balas, idb_balas, n1_balas = common.pecah(
                aes.decrypt(ka, pesan["data"]), 4
            )
        except ValueError:
            raise GagalKDC("Balasan tidak bisa dibuka dengan Ka; periksa Ka dan data KDC") from None

        if ida_balas != ida or idb_balas != idb or n1_balas != str(n1):
            raise GagalKDC("Identitas atau N1 pada balasan KDC tidak sesuai")
        masalah = common.cek_ks(ks)
        if masalah:
            raise GagalKDC(f"Session key dari KDC tidak valid: {masalah}")

        common.log(ida, f"  terverifikasi: Ks={ks}, IDA={ida_balas}, IDB={idb_balas}, N1={n1_balas}")
        return ks, pesan["ticket"]
    except GagalKDC:
        raise
    except (OSError, ValueError) as error:
        raise GagalKDC(f"Gagal berkomunikasi dengan KDC: {error}") from None
    finally:
        if sock is not None:
            sock.close()

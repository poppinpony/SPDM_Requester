"""
cli/main.py

SPDM Tool CLI 入口（Click）

使用範例：
  # 列出系統上支援 DOE 的 PCIe 裝置
  spdm-tool list-devices

  # 標準流程（VCA + 取憑證）
  spdm-tool --vid 0x1234 --devid 0xAB28 get-certificate --slot 0

  # 故意跳過 VCA，直接送 GET_CERTIFICATE → 觀察碟機回 0x7F
  spdm-tool --vid 0x1234 --devid 0xAB28 send-raw --hex "138200000000FFFF"

  # 跑完整 state machine 測試
  spdm-tool --vid 0x1234 --devid 0xAB28 test state-machine
"""

import logging
import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# 共用選項
# ──────────────────────────────────────────────────────────────────────────────

def transport_options(f):
    f = click.option("--vid",   type=lambda x: int(x, 0), default=None,
                     help="PCIe Vendor ID（e.g. 0x1234）")(f)
    f = click.option("--devid", type=lambda x: int(x, 0), default=None,
                     help="PCIe Device ID")(f)
    f = click.option("--timeout", type=int, default=5000,
                     help="Response timeout (ms)")(f)
    f = click.option("--mock", is_flag=True, default=False,
                     help="使用 MockTransport（不需要硬體）")(f)
    return f


def _make_transport(vid, devid, mock, timeout):
    if mock:
        from ..transport.mock import MockTransport
        return MockTransport()
    if vid is None or devid is None:
        raise click.UsageError("需要 --vid 和 --devid，或使用 --mock")
    from ..transport.doe import DoeTransport
    return DoeTransport(vid=vid, devid=devid)


def _make_requester(transport, timeout, version):
    from ..requester import SpdmRequester
    return SpdmRequester(transport, default_version=version, timeout_ms=timeout)


# ──────────────────────────────────────────────────────────────────────────────
# 主命令群組
# ──────────────────────────────────────────────────────────────────────────────

@click.group()
@click.option("--verbose", "-v", is_flag=True, help="顯示 debug 訊息")
@click.option("--spdm-version", default="1.3",
              type=click.Choice(["1.2", "1.3", "1.4"]),
              help="SPDM 版本")
@click.pass_context
def cli(ctx, verbose, spdm_version):
    """SPDM Requester Tool — SSD firmware validation"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    ctx.ensure_object(dict)
    ver_map = {"1.2": 0x12, "1.3": 0x13, "1.4": 0x14}
    ctx.obj["spdm_version"] = ver_map[spdm_version]


# ──────────────────────────────────────────────────────────────────────────────
# list-devices
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("list-devices")
def list_devices():
    """列出系統上支援 PCIe DOE 的裝置"""
    from ..transport.doe import list_doe_devices
    devs = list_doe_devices()
    if not devs:
        rprint("[yellow]找不到支援 DOE 的 PCIe 裝置[/yellow]")
        return
    t = Table(title="DOE 裝置清單")
    t.add_column("VID",   style="cyan")
    t.add_column("DevID", style="cyan")
    for vid, devid in devs:
        t.add_row(f"0x{vid:04X}", f"0x{devid:04X}")
    console.print(t)


# ──────────────────────────────────────────────────────────────────────────────
# send-raw：最低階，送任意 hex bytes
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("send-raw")
@transport_options
@click.option("--hex", "hex_str", required=True,
              help="要送出的 SPDM 訊息（hex 字串，空格可忽略）")
@click.pass_context
def send_raw(ctx, vid, devid, timeout, mock, hex_str):
    """送出任意 bytes，顯示 raw response（不走 state machine）"""
    data = bytes.fromhex(hex_str.replace(" ", ""))
    transport = _make_transport(vid, devid, mock, timeout)
    req = _make_requester(transport, timeout, ctx.obj["spdm_version"])
    try:
        rprint(f"[blue]TX[/blue] ({len(data)} bytes): {data.hex()}")
        resp = req.send_raw(data)
        rprint(f"[green]RX[/green] ({len(resp)} bytes): {resp.hex()}")
        # 嘗試解析
        from ..messages.base import SpdmMessage
        parsed = SpdmMessage.from_bytes(resp)
        rprint(f"[green]Parsed:[/green] {parsed!r}")
    finally:
        transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# vca：執行 Version + Capabilities + Algorithms
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("vca")
@transport_options
@click.pass_context
def vca(ctx, vid, devid, timeout, mock):
    """執行 VCA 三步驟（GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS）"""
    transport = _make_transport(vid, devid, mock, timeout)
    req = _make_requester(transport, timeout, ctx.obj["spdm_version"])
    try:
        v, c, a = req.do_vca()
        rprint("[bold green]VCA 完成[/bold green]")
        rprint(f"  VERSION:    {v!r}")
        rprint(f"  CAPABILTIES: {c!r}")
        rprint(f"  ALGORITHMS: {a!r}")
    finally:
        transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# get-certificate
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("get-certificate")
@transport_options
@click.option("--slot", type=int, default=0, help="Certificate slot (0-7)")
@click.option("--skip-vca", is_flag=True,
              help="故意跳過 VCA，直接送 GET_CERTIFICATE（測試 state machine）")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="儲存憑證鏈到檔案（DER 格式）")
@click.pass_context
def get_certificate(ctx, vid, devid, timeout, mock, slot, skip_vca, output):
    """取得憑證鏈（可選擇是否先執行 VCA）"""
    transport = _make_transport(vid, devid, mock, timeout)
    req = _make_requester(transport, timeout, ctx.obj["spdm_version"])
    try:
        if not skip_vca:
            req.do_vca()
        cert = req.do_get_certificate(slot=slot)
        if isinstance(cert, bytes):
            rprint(f"[green]憑證鏈取得成功：{len(cert)} bytes[/green]")
            if output:
                Path(output).write_bytes(cert)
                rprint(f"已儲存至 {output}")
        else:
            rprint(f"[red]錯誤回應：{cert!r}[/red]")
    finally:
        transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# get-measurements
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("get-measurements")
@transport_options
@click.option("--slot", type=int, default=0)
@click.option("--index", type=lambda x: int(x, 0), default=0xFF,
              help="Measurement index（0xFF=全部）")
@click.option("--no-sig", is_flag=True, help="不要求簽名")
@click.option("--skip-vca", is_flag=True)
@click.pass_context
def get_measurements(ctx, vid, devid, timeout, mock, slot, index, no_sig, skip_vca):
    """取得測量值"""
    transport = _make_transport(vid, devid, mock, timeout)
    req = _make_requester(transport, timeout, ctx.obj["spdm_version"])
    try:
        if not skip_vca:
            req.do_vca()
        resp = req.do_get_measurements(index=index, request_sig=not no_sig, slot=slot)
        from ..messages.measurements import MeasurementsResponse
        if isinstance(resp, MeasurementsResponse):
            rprint(f"[green]取得 {len(resp.blocks)} 個 Measurement Block[/green]")
            for blk in resp.blocks:
                rprint(f"  [{blk.index:#04x}] {blk.measurement.hex()}")
        else:
            rprint(f"[red]錯誤回應：{resp!r}[/red]")
    finally:
        transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# challenge
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("challenge")
@transport_options
@click.option("--slot", type=int, default=0)
@click.option("--meas-type", type=lambda x: int(x, 0), default=0x00,
              help="Measurement summary hash type（0=none, 0xFF=all）")
@click.option("--skip-vca", is_flag=True)
@click.pass_context
def challenge(ctx, vid, devid, timeout, mock, slot, meas_type, skip_vca):
    """執行 CHALLENGE 認證"""
    transport = _make_transport(vid, devid, mock, timeout)
    req = _make_requester(transport, timeout, ctx.obj["spdm_version"])
    try:
        if not skip_vca:
            req.do_vca()
            req.do_get_digests()
            req.do_get_certificate(slot=slot)
        resp = req.do_challenge(slot=slot, meas_type=meas_type)
        rprint(f"CHALLENGE_AUTH: {resp!r}")
    finally:
        transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# test：State machine 驗證測試集
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("test")
@transport_options
@click.argument("suite", type=click.Choice(["state-machine", "all"]))
@click.pass_context
def test(ctx, vid, devid, timeout, mock, suite):
    """執行 Spec 合規測試"""
    rprint(f"[yellow]測試套件 '{suite}' — 開發中...[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# 執行入口
# ──────────────────────────────────────────────────────────────────────────────

# Path import（部分 command 使用）
from pathlib import Path

if __name__ == "__main__":
    cli()

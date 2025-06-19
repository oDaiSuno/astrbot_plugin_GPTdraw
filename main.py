from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
import astrbot.api.message_components as Comp
from astrbot.api import logger
import json
import requests
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import uuid
import hmac
import hashlib
import base64
from datetime import datetime, timezone
import random
import os
import httpx
import aiohttp
import asyncio

proxies = None


class KontextFluxEncryptor:
    """
    Replicates the encryption logic from a.js to generate the 'xtx' header hash.
    """

    def __init__(self, config_data):
        self.kis = config_data["kis"]
        self.ra1 = config_data["ra1"]
        self.ra2 = config_data["ra2"]
        self.random = config_data["random"]

    def _aes_decrypt(self, key, iv, ciphertext_b64):
        """Decrypts AES-CBC base64 encoded data."""
        cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
        decoded_ciphertext = base64.b64decode(ciphertext_b64)
        decrypted_padded = cipher.decrypt(decoded_ciphertext)
        return unpad(decrypted_padded, AES.block_size).decode("utf-8")

    def _aes_encrypt(self, key, iv, plaintext):
        """Encrypts plaintext with AES-CBC and returns a base64 encoded string."""
        cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
        padded_data = pad(plaintext.encode("utf-8"), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode("utf-8")

    def get_xtx_hash(self, payload):
        """
        Generates the final MD5 hash for the 'xtx' header.

        Args:
            payload (dict): The request body/data to be encrypted.

        Returns:
            str: The MD5 hash string.
        """
        # Step 1: Serialize and encode the payload
        sorted_keys = sorted(payload.keys())
        serialized_parts = []
        for key in sorted_keys:
            value = payload[key]
            # Equivalent to JS: JSON.stringify -> replace -> btoa
            stringified_value = json.dumps(
                value, separators=(",", ":"), ensure_ascii=False
            )
            safe_value = stringified_value.replace("<", "").replace(">", "")
            encoded_value = base64.b64encode(safe_value.encode("utf-8")).decode("utf-8")
            serialized_parts.append(f"{key}={encoded_value}")

        serialized_payload = "".join(serialized_parts)

        # Step 2: Dynamically derive intermediate key and IV
        decoded_kis = base64.b64decode(self.kis).split(b"=sj+Ow2R/v")
        random_str = str(self.random)

        y = int(random_str[0])
        b = int(random_str[-1])
        k = int(random_str[2 : 2 + y])
        s_idx = int(random_str[4 + y : 4 + y + b])

        intermediate_key = decoded_kis[k].decode("utf-8")
        intermediate_iv = decoded_kis[s_idx].decode("utf-8")

        # Step 3: Decrypt to get the final AES key and IV
        main_key = self._aes_decrypt(intermediate_key, intermediate_iv, self.ra1)
        main_iv = self._aes_decrypt(intermediate_key, intermediate_iv, self.ra2)

        # Step 4: Encrypt the payload and compute the final MD5 hash
        encrypted_payload = self._aes_encrypt(main_key, main_iv, serialized_payload)
        final_hash = hashlib.md5(encrypted_payload.encode("utf-8")).hexdigest()

        return final_hash


async def getConfig():
    url = "https://api.kontextflux.com/client/common/getConfig"

    payload = {"token": None, "referrer": ""}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Content-Type": "application/json",
        "Origin": "https://kontextflux.com",
        "Referer": "https://kontextflux.com/",
    }

    async with httpx.AsyncClient(proxy=proxies["http"]) as client:
        response = await client.post(url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        return response.json()["data"]


async def uploadFile(config, file):
    url = "https://api.kontextflux.com/client/resource/uploadFile"

    files = [("file", (file.name, file, "null"))]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Authorization": config["token"],
        "xtx": KontextFluxEncryptor(config).get_xtx_hash({}),
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, files=files, headers=headers)
        response.raise_for_status()
        return response.json()["data"]


async def draw(config, prompt, keys=[], size="auto"):

    url = "https://api.kontextflux.com/client/styleAI/draw"

    payload = {
        "keys": keys,
        "prompt": prompt,
        "size": size,
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Content-Type": "application/json",
        "Authorization": config["token"],
        "xtx": KontextFluxEncryptor(config).get_xtx_hash(payload),
    }
    async with httpx.AsyncClient(proxy=proxies["http"]) as client:
        response = await client.post(url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        return response.json()["data"]["id"]


async def getDraw(config, drawId, timeout=120):
    e = {
        "token": config["token"],
        "id": drawId,
    }
    xtx = KontextFluxEncryptor(config).get_xtx_hash(e)
    url = f"wss://api.kontextflux.com/client/styleAI/checkWs?xtx={xtx}"
    result_url = None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(url, timeout=timeout) as ws:
                await ws.send_json(e)

                while not ws.closed:
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=timeout)

                        if msg.type in (
                            aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.ERROR,
                        ):
                            logger.warning(f"WebSocket closed or error: {msg.type}")
                            break

                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                                logger.info(f"data: {data}")
                                photo_info = data.get("content", {}).get("photo")
                                if photo_info:
                                    result_url = photo_info.get("url")

                                progress = data.get("content", {}).get("progress", -1)
                                yield progress, result_url

                                if result_url:
                                    break
                            except (json.JSONDecodeError, KeyError) as e:
                                logger.error(
                                    f"Error processing message: {msg.data}, exception: {e}"
                                )
                                continue

                    except asyncio.TimeoutError:
                        logger.error(f"WebSocket receive timeout for drawId: {drawId}")
                        break

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(
            f"WebSocket connection failed for drawId: {drawId}, exception: {e}"
        )
        return  # Terminate the generator


async def downloadFile(url, filename=None):
    filename = filename or str(uuid.uuid4()) + ".png"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, "wb") as f:
                f.write(response.content)
        print(f"下载完成: {filename}")
    except requests.exceptions.RequestException as e:
        print(f"下载失败: {e}")
    return filename


def hmac_function(t, n, hash_algorithm="sha256"):
    """
    模仿JavaScript的HMAC函数

    参数:
    t: 要加密的消息 (message)
    n: 密钥 (key)
    hash_algorithm: 哈希算法，默认SHA256

    返回: HMAC结果
    """
    # 确保输入是字节类型
    if isinstance(t, str):
        t = t.encode("utf-8")
    if isinstance(n, str):
        n = n.encode("utf-8")

    # 创建HMAC对象并计算
    h = hmac.new(n, t, getattr(hashlib, hash_algorithm))

    # 返回十六进制字符串（类似CryptoJS默认输出）
    return h.hexdigest()


def hmac_function_base64(t, n, hash_algorithm="sha256"):
    """
    返回base64编码的HMAC结果
    """
    if isinstance(t, str):
        t = t.encode("utf-8")
    if isinstance(n, str):
        n = n.encode("utf-8")

    h = hmac.new(n, t, getattr(hashlib, hash_algorithm))
    return base64.b64encode(h.digest()).decode("utf-8")


def get_x_ebg_param():
    # 生成时间戳字符串
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    # timestamp = "2025-06-18T09:30:57.469Z"

    # 模仿 s.Buffer.from(p).toString("base64")
    # 将字符串编码为字节，然后转为base64
    p = timestamp  # 这里p是时间戳字符串
    x_ebg_param = base64.b64encode(p.encode("utf-8")).decode("utf-8")

    return timestamp, x_ebg_param


async def watermarkremover(filename):
    pixb_cl_id = str(random.randint(1000000000, 9999999999))

    timestamp, x_ebg_param = get_x_ebg_param()

    n = "A4nzUYcDOZ"
    t = f"POST/service/public/transformation/v1.0/predictions/wm/remove{timestamp}{pixb_cl_id}"
    x_ebg_signature = hmac.new(
        n.encode("utf-8"), t.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    print(f"pixb_cl_id: {pixb_cl_id}")
    print(f"timestamp: {timestamp}")
    print(f"x_ebg_param: {x_ebg_param}")
    print(f"x_ebg_signature: {x_ebg_signature}")

    url = "https://api.watermarkremover.io/service/public/transformation/v1.0/predictions/wm/remove"

    payload = {"input.rem_text": "false", "input.rem_logo": "false", "retention": "1d"}

    # 使用with语句确保文件句柄正确关闭
    with open(filename, "rb") as file_handle:
        files = [("input.image", (filename, file_handle.read(), "image/png"))]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "x-ebg-signature": x_ebg_signature,
            "pixb-cl-id": pixb_cl_id,
            "x-ebg-param": x_ebg_param,
            "origin": "https://www.watermarkremover.io",
            "referer": "https://www.watermarkremover.io/",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url, data=payload, files=files, headers=headers, timeout=20
            )
    response.raise_for_status()

    result_id = response.json()["_id"]

    url = f"https://api.watermarkremover.io/service/public/transformation/v1.0/predictions/{result_id}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "origin": "https://www.watermarkremover.io",
        "referer": "https://www.watermarkremover.io/",
    }

    for _ in range(30):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)
                logger.info(f"response: {response.json()}")
            response.raise_for_status()
            if response.json()["status"] == "SUCCESS":
                output = response.json()["output"][0]
                try:
                    if os.path.exists(filename):
                        os.remove(filename)
                        print(f"成功删除临时文件: {filename}")
                except OSError as e:
                    print(f"删除文件时出现错误: {e}")
                time.sleep(1)
                return output
        except Exception as e:
            print(e)
            time.sleep(1)

    return None


def create_progress_bar(progress, width=10):
    """创建ASCII进度条"""
    filled = int(progress * width / 100)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {progress}%"


@register("drawGPT", "oDaiSuno", "一个简单的 GPT画图 插件", "0.0.1")
class MyPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    async def initialize(self):
        """可选择实现异步的插件初始化方法，当实例化该插件类之后会自动调用该方法。"""

    # 注册指令的装饰器。指令名为 helloworld。注册成功后，发送 `/helloworld` 就会触发这个指令，并回复 `你好, {user_name}!`
    @filter.command("drawGPT", alias={"画图", "绘图", "draw"})
    async def drawGPT(
        self, event: AstrMessageEvent, message: str = "", enhancement: str = ""
    ):

        if not message:
            yield event.plain_result(
                f"🧑‍🎨 哈喽呀~你想画什么呢？\n"
                f"你可以输入 '/draw 绘画内容 是否进行描述增强 --size 比例' 来调用我的全部功能呢！毕竟我是个相当聪明且专业的画家啊！\n"
                f"比如，当你使用--size，你就可以选择我们支持的比例调控呢！目前我们仅支持4种比例：'auto', '2:3', '3:2', '1:1'。\n"
                f"还有还有，如果你不太熟练使用绘画模型，我们支持增强你的描述，方法非常简单，只需在 '/draw 绘画内容 ' 后加上 '你想增强的方向' 即可（当然你也可以直接选择全面增强哦！🤩）。"
            )
        else:
            user_name = event.get_sender_name()
            yield event.plain_result(
                f"🥳 来辣来辣{user_name}，我知道你很急, 但你先别急！因为我要开始画图咯...{'不过我好像得先增强你的绘画意图...' if enhancement else ''}"
            )  # 发送一条纯文本消息
            size = (
                "auto"
                if "--size" not in message
                else message.split("--size")[-1].strip()
            )

            if enhancement:

                llm_response = await self.context.get_using_provider().text_chat(
                    f"本次用户希望绘画内容为：{message}\n本次用户希望进行描述增强的方向为：{enhancement}\n",
                    image_urls=[],
                    contexts=[],
                    system_prompt="""
                        你需要从用户的描述中提取其真实的绘画意图，并用常见的LLM绘画提示词进行标准化处理。同时提供中英文版本以便对照。
                        有时用户会在指令最后加上--size，此时你需要识别用户指定的size，可供选择的范围："auto", "2:3", "3:2", "1:1"，
                        如果用户没有指定或不在范围内，则默认"auto"。
                        注意：直接严格输出json格式字典，格式如下：{"chinese_prompt": "已标准化后的中文prompt", "english_prompt": "已标准化后的English prompt", "size": "auto"}
                        不得输出任何其他多余内容！
                    """,
                )
                # yield event.plain_result(llm_response.completion_text)
                try:
                    llm_response_json = json.loads(llm_response.completion_text)
                except json.JSONDecodeError:
                    llm_response = await self.context.get_using_provider().text_chat(
                        f"本次用户希望翻译的内容为：{message}",
                        image_urls=[],
                        contexts=[],
                        system_prompt="""
                            将用户给出的内容翻译成地道英文！直接输出翻译后的结果，严禁输出任何多余内容！
                        """,
                    )
                    llm_response_json = {
                        "chinese_prompt": message,
                        "english_prompt": llm_response.completion_text,
                        "size": "auto",
                    }

                yield event.plain_result(
                    f"🧑‍🎨 我懂了，我猜你想要画的是：{llm_response_json['chinese_prompt']}！\n"
                    f"为此，我设计了更专业的prompt：{llm_response_json['english_prompt']}！\n"
                    f"此次我们选择的size是：{llm_response_json['size']}！\n"
                    f"接下来，我会根据你的需求，开始绘制你的画作！"
                )
                message = llm_response_json["english_prompt"]
                size = llm_response_json["size"]

            config = await getConfig()
            draw_id = await draw(config, message, size=size)
            yield event.plain_result(f"🧑‍🎨 我已经开始画画啦，请稍等...")

            # 优化进度显示：只在关键节点显示，更加用户友好
            progress_thresholds = [3, 20, 45]
            shown_progress = set()
            final_url = None

            async for progress, result_url in getDraw(config, draw_id):
                if result_url:
                    final_url = result_url

                # 智能进度显示：只在关键节点输出消息
                for threshold in progress_thresholds:
                    if (
                        progress >= threshold
                        and threshold not in shown_progress
                        and not final_url
                    ):
                        shown_progress.add(threshold)
                        progress_bar = create_progress_bar(progress)
                        if threshold == 3:
                            yield event.plain_result(f"🎨 构思中... {progress_bar}")
                        elif threshold == 20:
                            yield event.plain_result(f"✨ 精细绘制中... {progress_bar}")
                        elif threshold >= 45:
                            yield event.plain_result(f"🔥 即将完成... {progress_bar}")
                        break

            if final_url:
                chain = [
                    Comp.At(qq=event.get_sender_id()),  # At 消息发送者
                    Comp.Plain(
                        "🧑‍🎨 嘿嘿嘿，我画好咯~请往下看...吗？\n 😥 桥豆麻袋，怎么有点瑕疵，让我再修补一下!"
                    ),
                ]
                yield event.chain_result(chain)

                filename = await downloadFile(final_url)
                watermarked_image = await watermarkremover(filename)
                if watermarked_image:
                    chain = [
                        Comp.At(qq=event.get_sender_id()),  # At 消息发送者
                        Comp.Plain(
                            "🧑‍🎨 这下彻底画完啦，请往下看！"
                        ),
                    ]
                    chain.append(Comp.Image.fromURL(watermarked_image))
                else:
                    chain = [
                        Comp.At(qq=event.get_sender_id()),  # At 消息发送者
                        Comp.Plain(
                            "😭 糟糕，图片修补失败了，只能给你一个半成品了..."
                        ),
                    ]
                    chain.append(Comp.Image.fromURL(final_url))
                yield event.chain_result(chain)
            else:
                yield event.plain_result(f"😭 糟糕，没画完，请稍后再试啦。")

    async def terminate(self):
        """可选择实现异步的插件销毁方法，当插件被卸载/停用时会调用。"""

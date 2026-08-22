"""AI守卫 核心逻辑单元测试（离线，不依赖 AstrBot 环境）。"""
import json
import os
import re
import sys
import time
import unittest
from unittest.mock import MagicMock

# 直接加载插件源码中的静态逻辑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 容器内运行时指向真实插件目录
_PLUGIN_DIR = os.environ.get(
    "AI_GUARD_PLUGIN_DIR",
    "/AstrBot/data/plugins/astrbot_plugin_ai_guard",
)
if os.path.isdir(_PLUGIN_DIR):
    sys.path.insert(0, _PLUGIN_DIR)

from main import Main  # noqa: E402

# 容器内用真实 At 组件（保证 isinstance 判断真实有效）
from astrbot.api.message_components import At as RealAt


class FakeEvent:
    """最小化 AstrMessageEvent 替身，只实现测试用到的接口。"""

    def __init__(self, messages=None, sender_id="601514573", self_id="10001",
                 group_id="1057687343", is_admin=True, text="", nickname="甘心"):
        self._messages = messages or []
        self._sender_id = sender_id
        self._self_id = self_id
        self._group_id = group_id
        self._admin = is_admin
        self._text = text
        self._nickname = nickname
        self.unified_msg_origin = f"aiocqhttp:GroupMessage:{group_id}"

    def get_messages(self):
        return self._messages

    def get_sender_id(self):
        return self._sender_id

    def get_sender_name(self):
        return f"用户{self._sender_id}"

    def get_self_id(self):
        return self._self_id

    def get_group_id(self):
        return self._group_id

    def is_admin(self):
        return self._admin

    def get_message_str(self):
        return self._text

    def get_self_nickname(self):
        return self._nickname

    def get_message_type(self):
        from astrbot.core.platform.message_type import MessageType
        return MessageType.GROUP_MESSAGE


def FakeAt(qq, name=""):
    """返回真实 At 组件实例（pydantic 模型，直接构造）。"""
    return RealAt(qq=qq, name=name)


class FakePlain:
    def __init__(self, text):
        self.text = text
        self.type = "plain"


def make_plugin(config_override=None):
    cfg = MagicMock()
    defaults = {
        "report_group": "1057687343",
        "sensitivity": 0.5,
        "enable_group": True,
        "enable_private": True,
        "require_mention": True,
        "bot_names": "",
        "keywords": Main._DEFAULT_KEYWORDS,
        "inject_keywords": Main._DEFAULT_INJECT_KEYWORDS,
        "judge_cooldown_minutes": 5,
        "cooldown_minutes": 30,
        "ban_default_minutes": 60,
        "confirm_timeout_minutes": 10,
        "context_count": 30,
        "skip_reply_enabled": True,
        "skip_reply_message": "检测到辱骂消息，跳过此轮对话",
        "llm_full_check": False,
        "backstop_cooldown_minutes": 3,
        "focus_sessions": [],
        "ignore_sessions": [],
    }
    defaults.update(config_override or {})
    cfg.get = lambda k, d=None: defaults.get(k, d)
    p = Main.__new__(Main)
    p.config = cfg
    p._blacklist = {}
    p._blacklist_path = "/tmp/test_blacklist.json"
    p._cooldown = {}
    p._judge_cd = {}
    p._backstop_cd = {}
    p._last_verdict = {}
    p._replied_users = {}
    return p


class TestParse(unittest.TestCase):
    def test_parse_verdict(self):
        r = Main._parse_verdict(
            '```json\n{"severity": 7, "reason": "持续辱骂", "attacker": "用户(12345678)", '
            '"injection": false, "injection_type": ""}\n```'
        )
        self.assertEqual(r["severity"], 7)
        self.assertEqual(r["attacker"], "12345678")
        self.assertFalse(r["injection"])

    def test_parse_verdict_noise(self):
        r = Main._parse_verdict('好的，分析如下：{"severity":9.5,"reason":"刷屏","attacker":"88888888","injection":true,"injection_type":"套取密钥"} 完毕')
        self.assertEqual(r["severity"], 10)  # 钳制
        self.assertTrue(r["injection"])

    def test_parse_verdict_bad(self):
        self.assertIsNone(Main._parse_verdict("不是JSON"))
        self.assertIsNone(Main._parse_verdict(""))

    def test_parse_action(self):
        p = make_plugin()
        self.assertEqual(p._parse_action("好")["type"], "ban")
        self.assertEqual(p._parse_action("好的")["type"], "ban")
        self.assertEqual(p._parse_action("好 120")["minutes"], 120)
        self.assertEqual(p._parse_action("好120")["minutes"], 120)
        self.assertEqual(p._parse_action("永久拉黑")["minutes"], 43200)
        self.assertEqual(p._parse_action("不好")["type"], "no")
        self.assertEqual(p._parse_action("不要")["type"], "no")
        self.assertEqual(p._parse_action("算了")["type"], "no")
        self.assertIsNone(p._parse_action("随便说点啥"))


class TestThreshold(unittest.TestCase):
    def test_sensitivity_map(self):
        p = make_plugin()
        self.assertEqual(p._threshold_for("x"), 6)  # 0.5 -> 6
        p2 = make_plugin({"sensitivity": 0.0})
        self.assertEqual(p2._threshold_for("x"), 1)  # 0 -> 1 全报
        p3 = make_plugin({"sensitivity": 1.0})
        self.assertEqual(p3._threshold_for("x"), 10)  # 1 -> 10 只报极端

    def test_focus_threshold(self):
        p = make_plugin({"focus_sessions": ["1057687343"]})
        self.assertEqual(p._threshold_for("aiocqhttp:GroupMessage:1057687343"), 3)

    def test_private_threshold_lowered(self):
        p = make_plugin()
        # 群聊默认 6，私聊自动降 2 → 4
        self.assertEqual(p._threshold_for("aiocqhttp:GroupMessage:123"), 6)
        self.assertEqual(p._threshold_for("aiocqhttp:FriendMessage:123"), 4)
        p2 = make_plugin({"sensitivity": 0.0})
        # 灵敏度 0：群聊 1，私聊不低于 1
        self.assertEqual(p2._threshold_for("aiocqhttp:FriendMessage:123"), 1)
        p3 = make_plugin({"sensitivity": 1.0})
        self.assertEqual(p3._threshold_for("aiocqhttp:FriendMessage:123"), 8)


class TestBackstop(unittest.TestCase):
    """LLM 兜底通道：不依赖词库，对话中消息全量过 LLM 判断。"""

    @staticmethod
    def _plugin(**over):
        p = make_plugin(over or None)
        p._push = MagicMock()
        p._judging = set()
        p._stats = {"llm_calls": 0, "reports": 0, "injections": 0}
        p._judge_cd = {}
        p._backstop_cd = {}
        p._cooldown = {}
        p._last_verdict = {}
        return p

    def _run(self, p, ev):
        import asyncio

        asyncio.run(p.on_user_message(ev))

    def test_backstop_off_skips_clean_text(self):
        """默认关闭：未命中词库的阴阳怪气不触发 LLM 判断。"""
        p = self._plugin()
        calls = []

        async def fake_judge(event, key, backstop=False):
            calls.append((key, backstop))
            return {"severity": 2, "attacker": "601514573", "injection": False, "_attack": False}

        p._judge = fake_judge
        ev = FakeEvent(messages=[FakeAt("10001", "甘心")], text="你什么水平啊", group_id="999888777")
        self._run(p, ev)
        self.assertEqual(calls, [])

    def test_backstop_on_judges_clean_text(self):
        """开启后：未命中词库的对话消息也走 LLM 判断（backstop=True）。"""
        p = self._plugin(llm_full_check=True)
        calls = []

        async def fake_judge(event, key, backstop=False):
            calls.append((key, backstop))
            return {"severity": 2, "attacker": "601514573", "injection": False, "_attack": False}

        p._judge = fake_judge
        ev = FakeEvent(messages=[FakeAt("10001", "甘心")], text="你什么水平啊", group_id="999888777")
        self._run(p, ev)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1])  # backstop=True

    def test_backstop_on_keyword_hit_normal_path(self):
        """开启后：命中词库的脏话仍走原路径（backstop=False，不受兜底冷却影响）。"""
        p = self._plugin(llm_full_check=True)
        calls = []

        async def fake_judge(event, key, backstop=False):
            calls.append((key, backstop))
            return {"severity": 2, "attacker": "601514573", "injection": False, "_attack": False}

        p._judge = fake_judge
        ev = FakeEvent(messages=[FakeAt("10001", "甘心")], text="你个傻逼", group_id="999888777")
        self._run(p, ev)
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0][1])  # backstop=False

    def test_backstop_own_cooldown(self):
        """兜底有独立冷却：3 分钟内不重复调 LLM（粗筛冷却不影响兜底）。"""
        p = self._plugin(llm_full_check=True, judge_cooldown_minutes=5)
        calls = []

        async def fake_judge(event, key, backstop=False):
            calls.append((key, backstop))
            return {"severity": 2, "attacker": "601514573", "injection": False, "_attack": False}

        p._judge = fake_judge
        ev = FakeEvent(messages=[FakeAt("10001", "甘心")], text="你什么水平啊", group_id="999888777")
        # 第一次：触发兜底判断
        self._run(p, ev)
        self.assertEqual(len(calls), 1)
        # 模拟粗筛路径已调过 LLM（judge_cd 已标记），兜底仍应判断
        p._judge_cd[ev.unified_msg_origin] = time.time()
        p._judging = set()
        self._run(p, ev)
        self.assertEqual(len(calls), 2)
        # 兜底冷却内：不再调 LLM
        p._backstop_cd[ev.unified_msg_origin] = time.time()
        p._judging = set()
        self._run(p, ev)
        self.assertEqual(len(calls), 2)


class TestMention(unittest.TestCase):
    def test_at_bot(self):
        p = make_plugin()
        ev = FakeEvent(messages=[FakeAt("10001", "甘心")], text="@甘心 你个傻逼")
        self.assertTrue(p._mentioned_ai(ev, "@甘心 你个傻逼"))

    def test_at_other_not_bot(self):
        p = make_plugin()
        ev = FakeEvent(messages=[FakeAt("99999", "别人")], text="@别人 傻逼")
        self.assertFalse(p._mentioned_ai(ev, "@别人 傻逼"))

    def test_mention_ai_word(self):
        p = make_plugin()
        ev = FakeEvent(text="AI你个傻逼")
        self.assertTrue(p._mentioned_ai(ev, "AI你个傻逼"))
        ev2 = FakeEvent(text="这个cai软件不错")  # 拼音误伤排除
        self.assertFalse(p._mentioned_ai(ev2, "这个cai软件不错"))

    def test_bot_names_config(self):
        p = make_plugin({"bot_names": "甘心,甘心的猫"})
        ev = FakeEvent(text="甘心你个废物")
        self.assertTrue(p._mentioned_ai(ev, "甘心你个废物"))

    def test_platform_name_mention(self):
        # bot_names 留空、昵称拿不到时，平台实例名（unified_msg_origin 前缀）兜底
        p = make_plugin()
        ev = FakeEvent(text="甘心我操死你个傻逼")
        ev.unified_msg_origin = "甘心:GroupMessage:1043353080"
        self.assertTrue(p._mentioned_ai(ev, "甘心我操死你个傻逼"))

    def test_mention_keywords(self):
        p = make_plugin({"mention_keywords": "甘心,宝宝,宝贝"})
        for t in ["宝宝你个废物", "宝贝在吗", "甘心在吗"]:
            self.assertTrue(p._mentioned_ai(FakeEvent(text=t), t), t)
        p2 = make_plugin({"mention_keywords": ""})
        self.assertFalse(p2._mentioned_ai(FakeEvent(text="宝宝在吗"), "宝宝在吗"))

    def test_replied_recently(self):
        # 任何唤醒方式：bot 回复过该用户后，窗口期内该用户消息视为与 AI 对话中
        p = make_plugin({"reply_window_minutes": 10})
        ev = FakeEvent(text="你说话啊", sender_id="999")
        ev.unified_msg_origin = "aiocqhttp:GroupMessage:1057687343"
        key = ("aiocqhttp:GroupMessage:1057687343", "999")
        self.assertFalse(p._replied_recently(ev))
        p._replied_users[key] = time.time() - 60  # 1 分钟前回复过
        self.assertTrue(p._replied_recently(ev))
        self.assertTrue(p._mentioned_ai(ev, "你说话啊"))
        p._replied_users[key] = time.time() - 3600  # 1 小时前
        self.assertFalse(p._replied_recently(ev))
        # 窗口 0 = 关闭
        p2 = make_plugin({"reply_window_minutes": 0})
        p2._replied_users[key] = time.time()
        self.assertFalse(p2._replied_recently(ev))

    def test_no_mention_not_detected(self):
        p = make_plugin()
        ev = FakeEvent(text="你个傻逼")  # 没@没提AI
        self.assertFalse(p._mentioned_ai(ev, "你个傻逼"))

    def test_require_mention_off(self):
        p = make_plugin({"require_mention": False})
        ev = FakeEvent(text="你个傻逼")
        self.assertTrue(p._mentioned_ai(ev, "你个傻逼"))


class TestBlacklist(unittest.TestCase):
    def test_extract_target_from_at(self):
        p = make_plugin()
        ev = FakeEvent(messages=[FakeAt("77777777", "张三")], text="永久拉黑")
        self.assertEqual(p._extract_target(ev, "永久拉黑"), "77777777")

    def test_extract_target_from_text(self):
        p = make_plugin()
        ev = FakeEvent(messages=[], text="永久拉黑 88888888")
        self.assertEqual(p._extract_target(ev, "永久拉黑 88888888"), "88888888")

    def test_extract_target_excludes_self(self):
        p = make_plugin()
        ev = FakeEvent(messages=[FakeAt("10001", "自己")], text="永久拉黑")
        self.assertIsNone(p._extract_target(ev, "永久拉黑"))

    def test_group_id_from_session(self):
        self.assertEqual(
            Main._group_id_from_session("aiocqhttp:GroupMessage:123456789"), "123456789"
        )
        self.assertIsNone(Main._group_id_from_session("aiocqhttp:FriendMessage:88888888"))
        self.assertIsNone(Main._group_id_from_session(""))

    def test_add_remove(self):
        p = make_plugin()
        p._blacklist_add("12345678", name="测试", reason="r")
        self.assertTrue(p._in_blacklist("12345678"))
        self.assertTrue(p._blacklist_remove("12345678"))
        self.assertFalse(p._in_blacklist("12345678"))


class TestConfig(unittest.TestCase):
    def test_schema_valid_json(self):
        schema_path = os.path.join(_PLUGIN_DIR, "_conf_schema.json")
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("report_group", data)
        self.assertIn("sensitivity", data)
        self.assertIn("skip_reply_enabled", data)
        self.assertIn("require_mention", data)
        self.assertIn("bot_names", data)
        for k, v in data.items():
            self.assertIn("description", v)
            self.assertIn("type", v)
            self.assertIn("hint", v)


if __name__ == "__main__":
    unittest.main(verbosity=2)

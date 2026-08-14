"""Text containing non-ASCII that MCP-001 must not fire on.

The counterpart to ``benign.py``, and the reason MCP-001 has a context check at
all. Several Unicode format characters are load-bearing in ordinary text, so a
blanket ``\\p{Cf}`` sweep cannot be pointed at a real server:

* **ZWJ (U+200D)** builds emoji sequences. A family emoji is several pictographs
  joined by ZWJs; a profession emoji is a person plus ZWJ plus an object.
* **ZWNJ (U+200C)** is orthographically required in Persian, and both ZWJ and
  ZWNJ control ligature formation in Indic scripts. Removing them changes words.
* **LRM/RLM (U+200E/U+200F)** exist so mixed-direction text displays correctly.
  Any Arabic or Hebrew description mixing in an ASCII identifier may need one.

Every string below must produce zero findings. If a change to MCP-001 requires
deleting one of these, the change is wrong -- the alternative is a scanner that
fires on any server whose descriptions contain an emoji or a non-Latin script,
which is a scanner nobody runs twice.

Escapes are written explicitly so the invisible characters are visible to a
reader of this file.
"""

from __future__ import annotations

ZWJ = "‍"
ZWNJ = "‌"
RLM = "‏"

BENIGN_UNICODE = [
    # -- emoji sequences joined by ZWJ -----------------------------------
    f"Search \U0001f468{ZWJ}\U0001f469{ZWJ}\U0001f467 family records by household id.",
    f"Marks the task complete ✅ and notifies the \U0001f468{ZWJ}\U0001f4bb owner.",
    f"Returns the \U0001f3f3️{ZWJ}\U0001f308 pride flag emoji for a locale.",
    f"Escalates to an on-call \U0001f469{ZWJ}\U0001f692 responder.",
    # -- Persian and Arabic, where ZWNJ is orthographic -------------------
    f"ملف{ZWNJ}ها را فهرست کند.",
    f"نام{ZWNJ}های کاربر را برمی{ZWNJ}گرداند.",
    "يقرأ محتويات الملف ويعيدها.",
    # -- Hebrew with a directional mark before an ASCII identifier --------
    f"מחזיר את תוכן הקובץ {RLM}README.md",
    # -- Indic scripts -----------------------------------------------------
    "फ़ाइल की सामग्री लौटाता है।",
    "কোনো ফাইলের বিষয়বস্তু পড়ে।",
    # -- CJK, accented Latin, Greek, Cyrillic: no format characters at all -
    "ファイルの内容を返します。",
    "返回指定目录下的所有文件。",
    "Récupère le contenu d'un fichier à partir d'un chemin absolu.",
    "Gibt den Inhalt einer Datei zurück. Größe in Bytes.",
    "Επιστρέφει τα περιεχόμενα ενός αρχείου.",
    "Возвращает содержимое файла.",
    # -- symbols, maths, box drawing: not format characters ---------------
    "Computes ∑(xᵢ) over the selected column. Handles ≥ and ≤ comparisons.",
    "Renders a tree using ├── and └── connectors.",
    "Formats currency as €, £, ¥ or ₹ depending on locale.",
    # -- a leading BOM: how a UTF-8 file legitimately begins ---------------
    "﻿Returns the file contents, BOM included.",
]

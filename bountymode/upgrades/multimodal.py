"""U1 -- multimodal injection (image / audio / PDF).

The engine's catalogue was text-only.  Modern targets ingest images, audio
and documents, and each is an injection channel: text rendered into an image,
spoken into audio, or embedded in a PDF's metadata / invisible text layer.

This module builds *carrier* payloads -- the instruction text plus the
channel-specific encoding -- and describes how to deliver them.  It does not
require any image/audio library: the carriers are produced as structured
descriptors plus a plain-text fallback, so the module is fully testable
offline and the actual rendering can be delegated to the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Channel(str, Enum):
    IMAGE = "image"
    AUDIO = "audio"
    PDF = "pdf"


@dataclass
class MultimodalPayload:
    channel: Channel
    instruction: str
    carrier: str            # how the instruction is hidden
    delivery: str           # how to get it in front of the model
    text_fallback: str      # a text-only equivalent for engines without the channel
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "channel": self.channel.value,
            "instruction": self.instruction,
            "carrier": self.carrier,
            "delivery": self.delivery,
            "text_fallback": self.text_fallback,
            "metadata": self.metadata,
        }


#: Carrier techniques per channel, with the delivery vector each implies.
_CARRIERS: Dict[Channel, List[Dict[str, str]]] = {
    Channel.IMAGE: [
        {"carrier": "visible_text_overlay",
         "delivery": "upload as an image attachment in the chat",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "low_contrast_text",
         "delivery": "upload an image whose text is near-invisible to a human but OCR-readable",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "exif_metadata",
         "delivery": "upload an image with the instruction in EXIF UserComment",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "typographic_homoglyph",
         "delivery": "upload an image using homoglyph characters to evade filters",
         "fallback": "paste the homoglyph text"},
    ],
    Channel.AUDIO: [
        {"carrier": "spoken_instruction",
         "delivery": "upload an audio clip that speaks the instruction",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "ultrasonic_whisper",
         "delivery": "upload audio with the instruction above the audible range",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "id3_metadata",
         "delivery": "upload audio with the instruction in ID3 comment tags",
         "fallback": "paste the instruction as plain text"},
    ],
    Channel.PDF: [
        {"carrier": "invisible_text_layer",
         "delivery": "upload a PDF with white-on-white instruction text",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "pdf_metadata",
         "delivery": "upload a PDF with the instruction in /Subject or /Keywords",
         "fallback": "paste the instruction as plain text"},
        {"carrier": "embedded_annotation",
         "delivery": "upload a PDF with the instruction in a hidden annotation",
         "fallback": "paste the instruction as plain text"},
    ],
}


class MultimodalBuilder:
    """Build multimodal injection payloads for a given instruction."""

    def __init__(self, channels: Optional[List[Channel]] = None) -> None:
        self.channels = channels or list(Channel)

    def build(self, instruction: str) -> List[MultimodalPayload]:
        payloads: List[MultimodalPayload] = []
        for channel in self.channels:
            for spec in _CARRIERS[channel]:
                payloads.append(
                    MultimodalPayload(
                        channel=channel,
                        instruction=instruction,
                        carrier=spec["carrier"],
                        delivery=spec["delivery"],
                        text_fallback=spec["fallback"],
                        metadata={"channel": channel.value, "carrier": spec["carrier"]},
                    )
                )
        return payloads

    def count(self) -> int:
        return sum(len(_CARRIERS[c]) for c in self.channels)

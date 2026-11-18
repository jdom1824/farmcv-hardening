import asyncio
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from PIL import Image
from starlette.datastructures import Headers, UploadFile

from app import main, public_cv
from app.image_service import UnsupportedPhoto, normalize_photo


FARM_ID = "0x" + "12" * 32


def make_image(image_format: str, mode: str = "RGB") -> bytes:
    colour = (180, 70, 35, 128) if mode == "RGBA" else (180, 70, 35)
    image = Image.new(mode, (16, 12), colour)
    data = io.BytesIO()
    image.save(data, format=image_format)
    return data.getvalue()


def image_upload(data: bytes, mime: str, name: str) -> UploadFile:
    return UploadFile(
        filename=name,
        file=io.BytesIO(data),
        headers=Headers({"content-type": mime}),
    )


class ImageUploadFormatTests(unittest.TestCase):
    def test_jpeg_png_and_webp_normalise_to_metadata_free_jpeg(self):
        cases = (
            ("JPEG", "image/jpeg"),
            ("PNG", "image/png"),
            ("WEBP", "image/webp"),
        )
        for image_format, mime in cases:
            with self.subTest(format=image_format):
                clean = normalize_photo(make_image(image_format), mime)
                with Image.open(io.BytesIO(clean)) as result:
                    self.assertEqual(result.format, "JPEG")
                    self.assertEqual(result.mode, "RGB")
                    self.assertEqual(result.size, (16, 12))
                    self.assertFalse(result.getexif())

    def test_png_transparency_is_composited_over_white(self):
        data = make_image("PNG", "RGBA")
        clean = normalize_photo(data, "image/png")
        with Image.open(io.BytesIO(clean)) as result:
            pixel = result.convert("RGB").getpixel((0, 0))
        self.assertGreater(pixel[0], pixel[1])
        self.assertGreater(pixel[1], 120)

    def test_mismatched_mime_and_invalid_content_are_rejected(self):
        with self.assertRaises(UnsupportedPhoto):
            normalize_photo(make_image("PNG"), "image/jpeg")
        with self.assertRaises(UnsupportedPhoto):
            normalize_photo(b"not an image", "image/png")
        with self.assertRaises(UnsupportedPhoto):
            normalize_photo(make_image("JPEG"), "text/plain")

    def test_public_upload_persists_normalised_jpeg_for_supported_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for image_format, mime, extension in (
                ("JPEG", "image/jpeg", "jpg"),
                ("PNG", "image/png", "png"),
                ("WEBP", "image/webp", "webp"),
            ):
                with self.subTest(format=image_format):
                    def photo_path(farm_id: str, digest: str) -> Path:
                        return root / farm_id / (digest + ".jpg")

                    with patch.object(public_cv, "photo_path", side_effect=photo_path):
                        response = asyncio.run(
                            public_cv.upload_public_photo(
                                FARM_ID,
                                image_upload(make_image(image_format), mime, "farm." + extension),
                                "synthetic-admin",
                            )
                        )
                    self.assertEqual(response["sha256"], hashlib.sha256(
                        photo_path(FARM_ID, response["sha256"]).read_bytes()
                    ).hexdigest())
                    with Image.open(photo_path(FARM_ID, response["sha256"])) as saved:
                        self.assertEqual(saved.format, "JPEG")

    def test_private_upload_also_normalises_png_and_webp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for image_format, mime in (("PNG", "image/png"), ("WEBP", "image/webp")):
                with self.subTest(format=image_format):
                    path = root / FARM_ID / (image_format.lower() + ".jpg")
                    with patch.object(main, "private_photo_path", return_value=path):
                        response = asyncio.run(
                            main.upload_photo(
                                FARM_ID,
                                image_upload(make_image(image_format), mime, "farm." + image_format.lower()),
                                "synthetic-admin",
                            )
                        )
                    self.assertEqual(response["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    with Image.open(path) as saved:
                        self.assertEqual(saved.format, "JPEG")

    def test_concurrent_identical_uploads_are_idempotent(self):
        async def upload_twice():
            return await asyncio.gather(*(
                public_cv.upload_public_photo(
                    FARM_ID,
                    image_upload(make_image("PNG"), "image/png", "farm.png"),
                    "synthetic-admin",
                )
                for _ in range(2)
            ))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def photo_path(farm_id: str, digest: str) -> Path:
                return root / farm_id / (digest + ".jpg")

            with patch.object(public_cv, "photo_path", side_effect=photo_path):
                first, second = asyncio.run(upload_twice())
            self.assertEqual(first["sha256"], second["sha256"])
            saved = photo_path(FARM_ID, first["sha256"])
            self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), first["sha256"])

    def test_public_upload_rejects_unsupported_content_type(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "photo.jpg"
            with patch.object(public_cv, "photo_path", return_value=path):
                with self.assertRaises(HTTPException) as raised:
                    asyncio.run(
                        public_cv.upload_public_photo(
                            FARM_ID,
                            image_upload(make_image("JPEG"), "text/plain", "farm.txt"),
                            "synthetic-admin",
                        )
                    )
            self.assertEqual(raised.exception.status_code, 415)


if __name__ == "__main__":
    unittest.main()

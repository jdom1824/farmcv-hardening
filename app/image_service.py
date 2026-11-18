"""Validate and normalise uploaded photographs to metadata-free JPEG."""

import io
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError


MIME_FORMATS = {
    "image/jpeg": "JPEG",
    "image/jpg": "JPEG",
    "image/pjpeg": "JPEG",
    "image/png": "PNG",
    "image/x-png": "PNG",
    "image/webp": "WEBP",
}
ALLOWED_FORMATS = frozenset(MIME_FORMATS.values())
MAX_IMAGE_PIXELS = 20_000_000
MAX_IMAGE_DIMENSIONS = (2400, 2400)


class UnsupportedPhoto(ValueError):
    """The upload is not a supported, valid, bounded raster photo."""


def normalize_photo(data: bytes, content_type: str | None) -> bytes:
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    expected_format = MIME_FORMATS.get(mime)
    if mime not in MIME_FORMATS and mime not in {"", "application/octet-stream", "binary/octet-stream"}:
        raise UnsupportedPhoto("unsupported image type")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                image_format = image.format
                if (
                    image_format not in ALLOWED_FORMATS
                    or (expected_format is not None and image_format != expected_format)
                    or image.width * image.height > MAX_IMAGE_PIXELS
                    or getattr(image, "is_animated", False)
                    or getattr(image, "n_frames", 1) != 1
                ):
                    raise UnsupportedPhoto("unsupported image content")
                image.verify()

            with Image.open(io.BytesIO(data)) as image:
                image.load()
                image = ImageOps.exif_transpose(image)
                image.thumbnail(MAX_IMAGE_DIMENSIONS)
                if "A" in image.getbands() or "transparency" in image.info:
                    foreground = image.convert("RGBA")
                    background = Image.new("RGBA", foreground.size, (255, 255, 255, 255))
                    background.alpha_composite(foreground)
                    clean = background.convert("RGB")
                else:
                    clean = image.convert("RGB")
                output = io.BytesIO()
                clean.save(output, format="JPEG", quality=88, optimize=True)
                return output.getvalue()
    except UnsupportedPhoto:
        raise
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError,
            Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise UnsupportedPhoto("invalid or oversized image") from exc

"""Generate the FW-Forge Windows icon from the anvil + forge-spark mark.

Renders each size NATIVELY (so 16/32px stay crisp) and drops the spark at the
smallest sizes where it would just be noise. Outputs fwforge.ico (16-256) and
fwforge-256.png, and prints the SVG-based favicon <link> for the webui.
Run: python gen_icon.py
"""
import base64
import math
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).parent
BRAND, BRAND_D = (38, 103, 152), (20, 60, 94)   # #266798 -> #143c5e
AMBER = (245, 166, 35)                           # #f5a623
WHITE = (246, 249, 251)
SIZES = [256, 128, 64, 48, 32, 16]


def _gradient_rounded(s, radius):
    grad = Image.new("RGB", (1, s))
    for y in range(s):
        t = y / (s - 1)
        grad.putpixel((0, y), tuple(
            int(BRAND[i] * (1 - t) + BRAND_D[i] * t) for i in range(3)))
    grad = grad.resize((s, s))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, s - 1, s - 1], radius=radius, fill=255)
    out = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    out.paste(grad, (0, 0), mask)
    return out


def _sc(pts, s):
    return [(x / 100 * s, y / 100 * s) for x, y in pts]


def _star(cx, cy, R, r):
    p = []
    for k in range(8):
        a = math.pi / 2 - k * math.pi / 4
        rad = R if k % 2 == 0 else r
        p.append((cx + rad * math.cos(a), cy - rad * math.sin(a)))
    return p


def render(size, spark=True):
    ss = 4
    s = size * ss
    img = _gradient_rounded(s, int(s * 0.22))
    d = ImageDraw.Draw(img)
    for poly in (
        _sc([(36, 36), (84, 36), (84, 51), (36, 51)], s),   # face
        _sc([(11, 47), (36, 36), (36, 51)], s),             # horn
        _sc([(45, 51), (61, 51), (59, 61), (47, 61)], s),   # neck
        _sc([(25, 76), (75, 76), (66, 61), (34, 61)], s),   # base
    ):
        d.polygon(poly, fill=WHITE)
    if spark:
        d.polygon(_star(0.77 * s, 0.24 * s, 0.12 * s, 0.04 * s), fill=AMBER)
    return img.resize((size, size), Image.LANCZOS)


# crisp 16px: render each size natively, drop the spark at <= 20px
imgs = [render(n, spark=(n > 20)) for n in SIZES]
ico = HERE / "fwforge.ico"
imgs[0].save(ico, format="ICO", append_images=imgs[1:],
             sizes=[(n, n) for n in SIZES])
render(256).save(HERE / "fwforge-256.png")

svg_b64 = base64.b64encode((HERE / "fwforge.svg").read_bytes()).decode()
print(f"wrote {ico.name} ({', '.join(map(str, SIZES))}px) + fwforge-256.png")
print('FAVICON_LINK=<link rel="icon" type="image/svg+xml" '
      f'href="data:image/svg+xml;base64,{svg_b64}">')

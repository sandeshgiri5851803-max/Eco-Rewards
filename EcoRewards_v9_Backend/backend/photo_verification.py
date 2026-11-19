"""Photo verification helpers.
PURPOSE: Compare internal uploaded images and flag possible matches for human review.
LIMITATION: These checks do not prove image authenticity or search the entire public web.
"""
"""Free, offline evidence similarity checks for EcoRewards.

PURPOSE: Flag photos for admin comparison; never declare fraud automatically.
SHA256 recognises identical original files. dHash finds nearby visual structure.
Crop comparison tests limited center/edge crops. This cannot search Google.
Uses Pillow only; no paid API keys or AI cloud services needed.
"""
import hashlib
from PIL import Image, ImageOps


def sha256_bytes(raw):
    """SHA-256 detects exact byte-for-byte reuse, even across accounts."""
    return hashlib.sha256(raw).hexdigest()


def dhash(im):
    """Difference hash of adjacent brightness values, 64 bits (16 hex chars)."""
    grey = ImageOps.grayscale(ImageOps.exif_transpose(im)).resize((9, 8))
    # Pillow 14 removes getdata(); this works on old and new versions.
    px = list(grey.get_flattened_data() if hasattr(grey, 'get_flattened_data') else grey.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row*9+col] > px[row*9+col+1])
    return f'{bits:016x}'


def crop_hashes(im):
    """Build fingerprints from common crops; useful but NOT angle-invariant."""
    w,h=im.size
    regions=[]
    for left,top,right,bottom in ((.0,.0,1,1),(.12,.12,.88,.88),(.22,.22,.78,.78),(.0,.0,.8,.8),(.2,0,1,.8),(0,.2,.8,1),(.2,.2,1,1)):
        box=(int(w*left),int(h*top),max(int(w*right),int(w*left)+1),max(int(h*bottom),int(h*top)+1))
        regions.append(dhash(im.crop(box)))
    return regions


def distance(a,b):
    """Hamming distance (number of differing bits) between 64-bit hashes."""
    if not a or not b or len(a)!=16 or len(b)!=16: return 64
    try:return bin(int(a,16)^int(b,16)).bit_count("1")
    except ValueError:return 64


def analyse_file(path,original_sha):
    """Run fingerprints on the safely decoded and normalised stored image."""
    with Image.open(path) as im:
        im=ImageOps.exif_transpose(im).convert('RGB')
        return {'sha256':original_sha,'dhash':dhash(im),'crops':crop_hashes(im)}


def compare(new,old):
    """Return signal and distance; avoid false-positive from one weak hash.

    Identical SHA is strong evidence of same file, NOT proof of dishonest intent.
    dHash collisions happen for flat/low-detail images. Near-identical hashes
    are only review hints and should be compared visually by an admin.
    """
    if new.get('sha256') and old.get('sha256')==new.get('sha256'):
        return {'kind':'exact_file','distance':0,'explanation':'The original uploaded file bytes are identical.'}
    d=distance(new.get('dhash'),old.get('dhash'))
    if d<=4:
        return {'kind':'similar_image','distance':d,'explanation':'Photo structure looks similar. Review both images.'}
    ca=new.get('crops') or [];cb=old.get('crops') or []
    # Only compare whole new image with old crops (or vice versa).
    # Avoid every-crop-to-every-crop matches because these are too noisy.
    dc=min([distance(new.get('dhash'),b) for b in cb[1:]]+[distance(old.get('dhash'),a) for a in ca[1:]] or [64])
    if dc<=3:
        return {'kind':'possible_crop','distance':dc,'explanation':'Potential cropped/reframed reuse; needs manual review.'}
    return None

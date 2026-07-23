import os
import struct
import zlib

def make_png(size, color=(255, 45, 85)):
    def chunk(name, data):
        c = zlib.crc32(name + data) & 0xffffffff
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', c)
    
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    row = b'\x00' + bytes(color) * size
    idat = zlib.compress(row * size)
    
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', ihdr) +
            chunk(b'IDAT', idat) +
            chunk(b'IEND', b''))

# Create icons folder inside extension/
icon_dir = os.path.join(os.path.dirname(__file__), '..', 'extension', 'icons')
os.makedirs(icon_dir, exist_ok=True)

for size in [16, 48, 128]:
    path = os.path.join(icon_dir, f'icon{size}.png')
    with open(path, 'wb') as f:
        f.write(make_png(size))
    print(f"✅ Created icon{size}.png")

print("\n🎉 All icons generated in extension/icons/")
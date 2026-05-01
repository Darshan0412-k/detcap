from PIL import Image, ImageDraw, ImageFont

# Canvas
img = Image.new("RGB", (1400, 500), (10, 10, 15))
draw = ImageDraw.Draw(img)

# Try better font (Windows default fallback safe)
try:
    font_title = ImageFont.truetype("arial.ttf", 80)
    font_sub = ImageFont.truetype("arial.ttf", 35)
    font_small = ImageFont.truetype("arial.ttf", 28)
except:
    font_title = ImageFont.load_default()
    font_sub = ImageFont.load_default()
    font_small = ImageFont.load_default()

# Colors (cyber style)
green = (0, 255, 140)
blue = (0, 180, 255)
white = (230, 230, 230)

# Title
draw.text((480, 120), "DETCAP", fill=green, font=font_title)

# Subtitle
draw.text((320, 220), "AI-POWERED CYBERSECURITY SCANNER", fill=white, font=font_sub)

# Tagline
draw.text((500, 300), "The Commit Crew", fill=blue, font=font_small)

# Footer line
draw.text((420, 360), "Network Recon • AI Analysis • Pentesting Tool", fill=(150,150,150), font=font_small)

# Save
img.save("detcap_banner.png")

print("🔥 New banner generated: detcap_banner.png")
Objective
To recover deleted video footage from an IP security camera by analyzing a .pcap network capture file, and retrieve a hidden flag left in the video frames.

Tools Used
foremost — for carving files based on file signatures

tshark — for exporting HTTP objects

Python (Scapy) — for manually extracting JPEGs from TCP data

Basic CLI tools: ls, wc, feh, etc.

Step-by-Step Process
Step 1: Run foremost to extract files

foremost -i security-footage-1648933966395.pcap -o extracted/
Result:
A directory extracted/ was created with various file types:

ls extracted/
audit.txt  jpg  png  pdf  mov  docx ... and more
However, the jpg/ folder was empty:

ls extracted/jpg/ | wc -l
0
Step 2: Attempt to extract HTTP objects with tshark

mkdir extracted_objects
tshark -r security-footage-1648933966395.pcap --export-objects http,extracted_objects/
Result:
The extracted_objects/ folder was also empty — indicating that the camera likely streamed video in an unusual way.

Step 3: Use a Python script (extract_jpeg.py) to extract JPEGs manually
The script searches for JPEG file signatures (hex: FFD8 to FFD9) in the raw packet data and extracts them:

extract_jpeg.py:
python
from scapy.all import *
import binascii

def extract_jpegs_from_pcap(pcap_file, output_dir="frames"):
    packets = rdpcap(pcap_file)
    data = b""

    for pkt in packets:
        if Raw in pkt:
            data += bytes(pkt[Raw].load)

    start = 0
    count = 0

    while True:
        soi = data.find(b'\xff\xd8', start)
        eoi = data.find(b'\xff\xd9', soi)

        if soi == -1 or eoi == -1:
            break

        jpg_data = data[soi:eoi+2]
        with open(f"{output_dir}/frame_{count:04}.jpg", "wb") as f:
            f.write(jpg_data)

        count += 1
        start = eoi + 2

    print(f"Extracted frames: {count}")

if __name__ == "__main__":
    import os
    os.makedirs("frames", exist_ok=True)
    extract_jpegs_from_pcap("security-footage-1648933966395.pcap")
Run the script:
pip install scapy
python3 extract_jpeg.py
Result:
A new folder frames/ was created:

ls frames/ | wc -l
229
229 images successfully extracted.

Step 4: View the frames
Preview the images:

feh frames/
Or play them like a flipbook:

for img in frames/*.jpg; do feh "$img"; sleep 0.1; done
Result
On frame_0229.jpg, the flag was clearly visible on a whiteboard:

flag{5ebf457ea66b2877fdbca2de9ec861}
Conclusion
Successfully carved over 200 individual frames from a .pcap file.

Used forensic tools and custom scripting to analyze MJPEG HTTP streams.

Verified that the camera transmitted JPEG frames directly.

The hidden flag was recovered through visual analysis.

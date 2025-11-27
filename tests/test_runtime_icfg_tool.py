
from vperify.runtime_icfg_tool import gen_runtime_icfg


def test_gen_runtime_icfg():
    main_binary = "/mnt/d/downloads/web_downloads/CC8160-VVTK_output/usr/sbin/httpd"
    rootfs = "/mnt/d/downloads/web_downloads/CC8160-VVTK_output"
    gen_runtime_icfg(argv=[main_binary], output_file="http_icfg.json", rootfs=rootfs)

if __name__ == "__main__":
    test_gen_runtime_icfg()

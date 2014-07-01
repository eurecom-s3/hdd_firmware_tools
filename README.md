hdd_firmware_tools
==================

This repository contains tools for HDD firmware extraction.
For more information, see [the presentation slides](http://s3.eurecom.fr/~zaddach/docs/Recon14_HDD.pdf) from Recon 2014.

- scripts/seagate_fw_extract.py Can extract Seagate HDD firmware files (.lod). The tool simply reads the executable file
  and splits it into parts. For each part, the contained meta-information is printed.

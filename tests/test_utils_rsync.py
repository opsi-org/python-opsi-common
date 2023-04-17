# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os.path
from pathlib import Path
import shutil
import random
import string
from itertools import combinations_with_replacement

import pytest

IMPORT_FAILED = False
try:
	from opsicommon.utils.rsync import librsync_delta_file, librsync_patch_file, librsync_signature
except ImportError:
	IMPORT_FAILED = True


@pytest.fixture
def librsync_testfile(tmp_path: Path) -> Path:
	data = (
		"Die NASA konnte wieder ein Funksignal der Sonde New Horizons empfangen. "
		"Damit scheint sicher, dass das Manöver ein Erfolg war und nun jede Menge Daten zu erwarten sind. "
		"Bis die alle auf der Erde sind, wird es aber dauern.\n"
		"\n"
		'Die NASA feiert eine "historische Nacht": '
		"Die Sonde New Horizons ist am Zwergplaneten Pluto vorbeigeflogen und hat kurz vor drei Uhr MESZ wieder "
		"Kontakt mit der Erde aufgenommen. Jubel, rotweißblaue Fähnchen und stehende Ovationen prägten die Stimmung "
		"im John Hopkins Labor in Maryland. Digital stellten sich prominente Gratulanten ein, "
		"von Stephen Hawking mit einer Videobotschaft bis zu US-Präsident Barack Obama per Twitter.\n"
		"\n"
		'"Hallo Welt"\n'
		"\n"
		"Das erste Funksignal New Horizons nach dem Vorbeiflug am Pluto brachte "
		"noch keine wissenschaftlichen Ergebnisse oder neue Fotos, sondern Telemetriedaten der Sonde selbst. "
		"Das war so geplant. Aus diesen Informationen geht hervor, dass es New Horizons gut geht, "
		"dass sie ihren Kurs hält und die vorausberechnete Menge an Speichersektoren belegt ist. "
		"Daraus schließen die Verantwortlichen der NASA, dass auch tatsächlich wissenschaftliche Informationen "
		"im geplanten Ausmaß gesammelt wurden."
	)
	testfile = tmp_path / "librsync_signature.txt"
	testfile.write_text(data, "utf-8")
	return testfile


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_signature_base64_encoded(librsync_testfile: Path) -> None:  # pylint: disable=redefined-outer-name
	assert librsync_signature(librsync_testfile) in (
		"cnMBNgAACAAAAAAI/6410IBmvH1GKbBN\n",  # librsync1
		"cnMBNwAACAAAAAAI/6410EtC5dhLF6sI\n",  # librsync2
	)


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_signature_creation(librsync_testfile: Path) -> None:  # pylint: disable=redefined-outer-name
	signature = librsync_signature(librsync_testfile, base64_encoded=False)
	assert signature in (
		b"rs\x016\x00\x00\x08\x00\x00\x00\x00\x08\xff\xae5\xd0\x80f\xbc}F)\xb0M",  # librsync1
		b"rs\x017\x00\x00\x08\x00\x00\x00\x00\x08\xff\xae5\xd0KB\xe5\xd8K\x17\xab\x08",  # librsync2
	)


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_delta_file_creation(librsync_testfile: Path, tmp_path: Path) -> None:  # pylint: disable=redefined-outer-name
	deltafile = tmp_path / "delta"
	oldfile = tmp_path / "old"
	oldfile.write_bytes(b"olddata")
	signature = librsync_signature(oldfile, base64_encoded=False)

	librsync_delta_file(librsync_testfile, signature.strip(), deltafile)
	assert deltafile.exists(), "No delta file was created"

	expected_delta = b"rs\x026B\x04\x8a" + librsync_testfile.read_bytes() + b"\x00"
	assert deltafile.read_bytes() == expected_delta


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_delta_size(tmp_path: Path) -> None:
	base_file = tmp_path / "base"
	oldfile = tmp_path / "old"
	delta_file = tmp_path / "base.delta"
	size = 1 * 1024 * 1024  # 1MiB

	data = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))
	base_file.write_text(data, encoding="utf-8")
	oldfile.write_text(data[: int(size / 2)], encoding="utf-8")

	signature = librsync_signature(oldfile, False)
	librsync_delta_file(base_file, signature, delta_file)
	delta_size = os.path.getsize(delta_file)
	assert delta_size < size * 0.51


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_patch_file_does_not_alter_if_unneeded(
	librsync_testfile: Path, tmp_path: Path  # pylint: disable=redefined-outer-name
) -> None:
	base_file = librsync_testfile
	oldfile = tmp_path / "old"
	delta_file = tmp_path / "base.delta"

	shutil.copy(base_file, oldfile)
	signature = librsync_signature(oldfile, False)
	librsync_delta_file(base_file, signature, delta_file)

	assert delta_file.exists()
	expected_delta = b"rs\x026F\x00\x04\x8a\x00"
	assert delta_file.read_bytes() == expected_delta

	newfile = tmp_path / "new_file.txt"
	librsync_patch_file(oldfile, delta_file, newfile)
	assert newfile.exists()

	with open(newfile, "rb") as new_f:
		with open(base_file, "rb") as base_f:
			assert base_f.readlines() == new_f.readlines()


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
def test_librsync_patch_file_creates_new_file_based_on_delta(
	librsync_testfile: Path, tmp_path: Path  # pylint: disable=redefined-outer-name
) -> None:
	base_file = librsync_testfile
	signature = librsync_signature(base_file, False)

	new_file = tmp_path / "oldnew.txt"
	shutil.copy(base_file, new_file)

	additional_text = "Und diese Zeile hier macht den Unterschied."

	with open(new_file, mode="a", encoding="utf-8") as file:
		file.write(f"\n\n{additional_text}\n")

	delta_file_for_new_file = tmp_path / "new_delta.delta"
	librsync_delta_file(new_file, signature, delta_file_for_new_file)
	expected_delta = (
		b"rs\x026B\x04\xb8Die NASA konnte wieder ein Funksignal der "
		b"Sonde New Horizons empfangen. Damit scheint sicher, dass "
		b"das Man\xc3\xb6ver ein Erfolg war und nun jede Menge Daten "
		b"zu erwarten sind. Bis die alle auf der Erde sind, wird es "
		b'aber dauern.\n\nDie NASA feiert eine "historische Nacht": '
		b"Die Sonde New Horizons ist am Zwergplaneten Pluto "
		b"vorbeigeflogen und hat kurz vor drei Uhr MESZ wieder Kontakt "
		b"mit der Erde aufgenommen. Jubel, rotwei\xc3\x9fblaue "
		b"F\xc3\xa4hnchen und stehende Ovationen pr\xc3\xa4gten die "
		b"Stimmung im John Hopkins Labor in Maryland. Digital stellten "
		b"sich prominente Gratulanten ein, von Stephen Hawking mit "
		b"einer Videobotschaft bis zu US-Pr\xc3\xa4sident Barack Obama "
		b'per Twitter.\n\n"Hallo Welt"\n\nDas erste Funksignal New '
		b"Horizons nach dem Vorbeiflug am Pluto brachte noch keine "
		b"wissenschaftlichen Ergebnisse oder neue Fotos, sondern "
		b"Telemetriedaten der Sonde selbst. Das war so geplant. "
		b"Aus diesen Informationen geht hervor, dass es New Horizons "
		b"gut geht, dass sie ihren Kurs h\xc3\xa4lt und die "
		b"vorausberechnete Menge an Speichersektoren belegt ist. "
		b"Daraus schlie\xc3\x9fen die Verantwortlichen der NASA, dass "
		b"auch tats\xc3\xa4chlich wissenschaftliche Informationen im "
		b"geplanten Ausma\xc3\x9f gesammelt wurden.\n\nUnd diese Zeile "
		b"hier macht den Unterschied.\n\x00"
	)

	assert delta_file_for_new_file.read_bytes() == expected_delta

	file_based_on_delta = tmp_path / "newnew.txt"
	librsync_patch_file(base_file, delta_file_for_new_file, file_based_on_delta)
	with open(new_file, mode="r", encoding="utf-8") as new_f:
		with open(file_based_on_delta, mode="r", encoding="utf-8") as new_f2:
			assert new_f.readlines() == new_f2.readlines()

	with open(file_based_on_delta, mode="r", encoding="utf-8") as new_f2:
		assert any(additional_text in line for line in new_f2)


@pytest.mark.skipif(IMPORT_FAILED, reason="Import failed.")
@pytest.mark.parametrize("old, delta, new", list(combinations_with_replacement(("foo", "bar"), 3)))
def test_librsync_patch_file_avoids_patching_same_file(old: str, delta: str, new: str) -> None:
	with pytest.raises(ValueError):
		librsync_patch_file(old, delta, new)

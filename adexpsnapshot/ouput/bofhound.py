"""BOFHound output mode - outputs objects in BOFHound log format."""
import base64
import datetime
import logging
import os
import queue
import threading
from rich.console import Console
from rich.progress import track


class BOFHoundEncoder:
    """Encoder for BOFHound log format."""
    
    timestamp_attributes = ['whenCreated', 'whenChanged', 'dSCorePropagationData']

    def encode(self, obj):
        if obj is None:
            return ""
        elif isinstance(obj, dict):
            return self.encode_dict(obj)
        elif isinstance(obj, list):
            return ", ".join(self.encode(item) for item in obj)
        elif isinstance(obj, int):
            return str(obj if obj < 0x80000000 else obj - 0x100000000)
        elif isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        elif isinstance(obj, (str, float, bool)):
            return str(obj)
        else:
            raise Exception(f"BOFHoundEncoder does not support objects of type {type(obj)}")

    def encode_dict(self, obj):
        lines = []
        for key in sorted(obj.keys()):
            if key in BOFHoundEncoder.timestamp_attributes:
                encoded = self.encode_timestamp(obj[key], key)
            else:
                encoded = self.encode(obj[key])
            lines.append(f"{key}: {encoded}")
        if len(lines):
            lines.append("")
        return "\n".join(lines)

    def encode_timestamp(self, value, attr=''):
        try:
            if isinstance(value, list):
                if len(value) == 0:
                    return "0"
                value = value[0] & 0xFFFFFFFF
            return datetime.datetime.fromtimestamp(value, datetime.UTC).strftime('%Y%m%d%H%M%S.0Z')
        except (TypeError, ValueError, OSError, OverflowError):
            logging.warning(f"Failed to parse timestamp for attribute {attr}")
            return "0"


class BOFHoundOutput:
    """Handles BOFHound-specific output processing."""
    
    def __init__(self, snapshot, output_folder, console: Console):
        self.snap = snapshot
        self.output = output_folder
        self.console = console
        self.outputfile = f"{snapshot.header.server}_{snapshot.header.filetimeUnix}_bofhound.log"
        self.encoder = BOFHoundEncoder()

    def process(self):
        """Process all objects and output to BOFHound log file."""
        def write_worker(result_q, filename):
            try:
                fh_out = open(filename, "w", encoding="utf-8")
            except OSError as exc:
                logging.warning("Could not write file %s: %s", filename, exc)
                # Drain queue so producer can finish cleanly without deadlocking on join().
                while True:
                    data = result_q.get()
                    result_q.task_done()
                    if data is None:
                        break
                return

            wrote_once = False
            with fh_out:
                while True:
                    data = result_q.get()

                    if data is None:
                        break

                    if not wrote_once:
                        wrote_once = True
                    else:
                        fh_out.write('--------------------\n')

                    try:
                        encoded_member = self.encoder.encode(data)
                        fh_out.write(encoded_member)
                    except TypeError:
                        logging.error("Data error %r, could not convert data to BOFHound log", data)
                    result_q.task_done()
            result_q.task_done()

        wq = queue.Queue()
        results_worker = threading.Thread(target=write_worker, args=(wq, os.path.join(self.output, self.outputfile)))
        results_worker.daemon = True
        results_worker.start()

        for obj in track(self.snap.objects, description="Dumping objects", total=self.snap.header.numObjects):
            wq.put(dict(obj.attributes.data))

        wq.put(None)
        wq.join()

        self.console.print(f"[green]✓[/green] Output written to {self.outputfile}")

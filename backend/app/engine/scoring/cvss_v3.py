import math
from typing import Dict, Any

class CVSSv31Calculator:
    """
    Kalkulator Base Score CVSS v3.1 lengkap sesuai spesifikasi FIRST.org.
    """

    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},      # Attack Vector: Network, Adjacent, Local, Physical
        "AC": {"L": 0.77, "H": 0.44},                            # Attack Complexity: Low, High
        "PR": {                                                   # Privileges Required: None, Low, High (Scope Unchanged vs Changed)
            "N": (0.85, 0.85),
            "L": (0.62, 0.68),
            "H": (0.27, 0.50)
        },
        "UI": {"N": 0.85, "R": 0.62},                            # User Interaction: None, Required
        "S": {"U": False, "C": True},                             # Scope: Unchanged, Changed
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},                   # Confidentiality: None, Low, High
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},                   # Integrity: None, Low, High
        "A": {"N": 0.0, "L": 0.22, "H": 0.56}                    # Availability: None, Low, High
    }

    @classmethod
    def calculate(cls, vector_str: str) -> Dict[str, Any]:
        """
        Menghitung skor CVSS v3.1 dan mengembalikan skor beserta rating kualitatif.
        """
        if not vector_str:
            return {"score": 0.0, "severity": "Info", "vector": ""}

        try:
            clean_vector = vector_str.replace("CVSS:3.1/", "")
            parts = {item.split(":")[0]: item.split(":")[1] for item in clean_vector.split("/") if ":" in item}

            scope_changed = cls.METRICS["S"].get(parts.get("S", "U"), False)
            
            c_val = cls.METRICS["C"].get(parts.get("C", "N"), 0.0)
            i_val = cls.METRICS["I"].get(parts.get("I", "N"), 0.0)
            a_val = cls.METRICS["A"].get(parts.get("A", "N"), 0.0)

            iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

            if scope_changed:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            else:
                impact = 6.42 * iss

            pr_metric = cls.METRICS["PR"].get(parts.get("PR", "N"), (0.85, 0.85))
            pr_val = pr_metric[1] if scope_changed else pr_metric[0]

            av_val = cls.METRICS["AV"].get(parts.get("AV", "N"), 0.85)
            ac_val = cls.METRICS["AC"].get(parts.get("AC", "L"), 0.77)
            ui_val = cls.METRICS["UI"].get(parts.get("UI", "N"), 0.85)

            exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

            if impact <= 0:
                base_score = 0.0
            else:
                if scope_changed:
                    raw_score = min(1.08 * (impact + exploitability), 10.0)
                else:
                    raw_score = min(impact + exploitability, 10.0)
                # Official CVSS roundup (nearest 0.1)
                base_score = round(math.ceil(raw_score * 10) / 10, 1)

            # Rating mapping
            if base_score == 0.0:
                sev = "Info"
            elif base_score < 4.0:
                sev = "Low"
            elif base_score < 7.0:
                sev = "Medium"
            elif base_score < 9.0:
                sev = "High"
            else:
                sev = "Critical"

            return {
                "score": base_score,
                "severity": sev,
                "vector": vector_str
            }
        except Exception:
            return {"score": 5.0, "severity": "Medium", "vector": vector_str}

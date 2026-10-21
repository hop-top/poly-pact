# Q5: jsonschema Draft202012Validator + referencing registry over pact.schema.json, offline; format checker coverage.
import base64, json, pathlib, re, socket
from jsonschema import Draft202012Validator as V
from referencing import Registry, Resource
def blocked(*a, **k): raise OSError("network blocked")
socket.socket = socket.create_connection = socket.getaddrinfo = blocked
spec = pathlib.Path(__file__).resolve().parents[4] / "spec" / "v1.0"
text = (spec / "schemas/pact.schema.json").read_text(); schema = json.loads(text)
payload = (spec / "fixtures/parse/appendix-c-wrong-version.jws").read_text().split(".")[1]
doc = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
reg = Registry().with_resource(schema["$id"], Resource.from_contents(schema)); V.check_schema(schema)
def errors(inst, registry=reg, fmt=True):
    v = V({"$ref": schema["$id"] + "#/$defs/Evidence"}, registry=registry, format_checker=V.FORMAT_CHECKER if fmt else None)
    try: return sorted(e.validator + "@/" + "/".join(map(str, e.absolute_path)) for e in v.iter_errors(inst))
    except Exception as e: return "RAISED " + type(e).__name__
print("formats the schema uses:", sorted(set(re.findall(r'"format"\s*:\s*"([^"]+)"', text))), "| checkers available:", sorted(V.FORMAT_CHECKER.checkers))
print("fixture as-is:", errors(doc), "| without registry:", errors(doc, registry=Registry()))
doc["pact_version"] = "0.1"; print("pact_version 0.1:", errors(doc), "| root oneOf valid:", V(schema, registry=reg).is_valid(doc))
doc["iss"] = "not a uri"; print("iss='not a uri' format on:", errors(doc), "| format off:", errors(doc, fmt=False))
doc["iat"] = 2**53; print("iat=2**53:", errors(doc)); doc["iat"] = 2.0; print("iat=2.0 (float):", errors(doc))

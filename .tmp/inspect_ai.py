import inspect, importlib, traceback
m = importlib.import_module('backend.services.ai_reasoning')
inst = m.ai_reasoning
print('has ai_reasoning', hasattr(m,'ai_reasoning'))
print('type', type(inst))
print('class methods:', [n for n,_ in inspect.getmembers(m.LocalAIReasoningEngine) if any(k in n for k in ('configure','ollama','get_ollama'))])
print('instance members sample:', [n for n,_ in inspect.getmembers(inst) if any(k in n for k in ('configure','ollama','get_ollama'))])
print('hasattr(instance, configure_ollama)=', hasattr(inst,'configure_ollama'))
print('hasattr(instance, get_ollama_status)=', hasattr(inst,'get_ollama_status'))
try:
    fn = getattr(m.LocalAIReasoningEngine,'configure_ollama')
    bound = fn.__get__(inst, m.LocalAIReasoningEngine)
    setattr(inst,'configure_ollama', bound)
    print('bound via setattr OK')
except Exception:
    print('setattr failed')
    traceback.print_exc()
print('after setattr, hasattr configure_ollama=', hasattr(inst,'configure_ollama'))
print('callable?', callable(getattr(inst,'configure_ollama', None)))

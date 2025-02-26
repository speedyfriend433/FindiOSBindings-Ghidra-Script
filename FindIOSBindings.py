# FindIOSBindings.py
# Ghidra script to find matching functions between iOS and Android binaries
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function
from ghidra.util.task import TaskMonitor
from java.util import ArrayList

class FunctionSignature:
    def __init__(self, name, basic_blocks_count, calls, string_refs):
        self.name = name
        self.basic_blocks_count = basic_blocks_count
        self.calls = calls
        self.string_refs = string_refs

class FindIOSBindings(GhidraScript):

    def calculate_similarity(self, sig1, sig2):
        score = 0
        
        if abs(sig1.basic_blocks_count - sig2.basic_blocks_count) <= 2:
            score += 30
        
        common_calls = set(sig1.calls) & set(sig2.calls)
        if len(common_calls) > 0:
            score += 40 * (len(common_calls) / max(len(sig1.calls), len(sig2.calls)))
        
        common_strings = set(sig1.string_refs) & set(sig2.string_refs)
        if len(common_strings) > 0:
            score += 30 * (len(common_strings) / max(len(sig1.string_refs), len(sig2.string_refs)))
        
        return score

    def run(self):
        android_sigs_file = self.askFile("Select Android binary signatures file", "Open")

        android_signatures = []
        try:
            with open(str(android_sigs_file.getAbsolutePath()), 'r') as f:
                import json
                android_signatures = json.load(f)
        except:
            self.println("Error loading Android signatures file")
            return

        program = getCurrentProgram()
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)
        
        ios_signatures = []
        for function in functions:
            if function.getName().startswith('FUN_'):
                signature = self.analyze_function(function)
                ios_signatures.append(signature)
        
        matches = []
        for ios_sig in ios_signatures:
            best_match = None
            best_score = 0
            
            for android_sig in android_signatures:
                score = self.calculate_similarity(ios_sig, android_sig)
                if score > 70 and score > best_score:  
                    best_score = score
                    best_match = android_sig
            
            if best_match:
                matches.append((ios_sig, best_match, best_score))
                function = getFunction(ios_sig.name)
                if function:
                    new_name = best_match.name
                    function.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        
        self.println('Found {} matching functions'.format(len(matches)))
        for ios_sig, android_sig, score in matches:
            self.println('Matched {} -> {} (score: {:.2f}%)'.format(
                ios_sig.name, android_sig.name, score))
        
    def analyze_function(self, function):
        basic_blocks = function.getBody().getBasicBlocks()
        basic_blocks_count = len(basic_blocks)
        
        calls = []
        refs = getReferencesFrom(function.getEntryPoint())
        for ref in refs:
            if ref.getReferenceType().isCall():
                called_function = getFunctionAt(ref.getToAddress())
                if called_function is not None:
                    calls.append(called_function.getName())
        
        string_refs = []
        listing = getCurrentProgram().getListing()
        addrSet = function.getBody()
        instructions = listing.getInstructions(addrSet, True)
        for instruction in instructions:
            refs = getReferencesFrom(instruction.getAddress())
            for ref in refs:
                if ref.getReferenceType().isData():
                    data = getDataAt(ref.getToAddress())
                    if data is not None and data.isString():
                        string_refs.append(str(data.getValue()))
        
        return FunctionSignature(
            function.getName(),
            basic_blocks_count,
            calls,
            string_refs
        )

if __name__ == '__main__':
    try:
        state = getState()
        script = FindIOSBindings()
        script.setState(state)
        script.run()
    except Exception as e:
        print(f"Error running script: {str(e)}")

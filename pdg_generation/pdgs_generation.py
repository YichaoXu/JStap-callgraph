# Copyright (C) 2019 Aurore Fass
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
    Generation and storage of JavaScript PDGs. Possibility for multiprocessing (NUM_WORKERS
    defined in utility_df.py).
"""

import pickle, psutil
from multiprocessing import Process, Queue
from typing import Callable, Generator, List, Optional

from .utility_df import *
from .handle_json import *
from .build_cfg import *
from .build_dfg import *
from .var_list import *
from .display_graph import *


GIT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def pickle_dump_process(dfg_nodes: Node, store_pdg):
    """ Call to pickle.dump """
    pickle.dump(dfg_nodes, open(store_pdg, 'wb'))


def get_data_flow(input_file, benchmarks, store_pdgs=None, check_var=False,
                  save_path_ast=False, save_path_cfg=False, save_path_pdg=False):
    """
        Produces the PDG of a given file.

        -------
        Parameters:
        - input_file: str
            Path of the file to study.
        - benchmarks: dict
            Contains the different microbenchmarks. Should be empty.
        - store_pdgs: str
            Path of the folder to store the PDG in.
            Or None to pursue without storing it.
        check_var: bool
            Build PDG just to check if our malicious variables are undefined. Default: False.
        - save_path_ast / cfg / pdg:
            False --> does neither produce nor store the graphical representation;
            None --> produces + displays the graphical representation;
            Valid-path --> Produces + stores the graphical representation under the name Valid-path.


        -------
        Returns:
        - Node
            PDG of the file
        - or None.
    """

    start = timeit.default_timer()
    if input_file.endswith('.js'):
        esprima_json = input_file.replace('.js', '.json')
    else:
        esprima_json = input_file + '.json'
    extended_ast = get_extended_ast(input_file, esprima_json)
    if extended_ast is not None:
        benchmarks['got AST'] = timeit.default_timer() - start
        start = micro_benchmark('Successfully got Esprima AST in', timeit.default_timer() - start)
        ast = extended_ast.get_ast()
        # beautiful_print_ast(ast, delete_leaf=[])
        ast_nodes = ast_to_ast_nodes(ast, ast_nodes=Node('Program'))
        # ast_nodes = search_dynamic(ast_nodes)  # Tried to handle dynamically generated JS
        benchmarks['AST'] = timeit.default_timer() - start
        start = micro_benchmark('Successfully produced the AST in', timeit.default_timer() - start)
        if save_path_ast is not False:
            draw_ast(ast_nodes, attributes=True, save_path=save_path_ast)
        cfg_nodes = build_cfg(ast_nodes)
        benchmarks['CFG'] = timeit.default_timer() - start
        start = micro_benchmark('Successfully produced the CFG in', timeit.default_timer() - start)
        if save_path_cfg is not False:
            draw_cfg(cfg_nodes, attributes=True, save_path=save_path_cfg)
        unknown_var = []
        try:
            with Timeout(60):  # Tries to produce DF within 60s
                dfg_nodes = df_scoping(cfg_nodes, var_loc=VarList(), var_glob=VarList(),
                                       unknown_var=unknown_var, id_list=[], entry=1)[0]
        except Timeout.Timeout:
            logging.exception('Timed out for %s', input_file)
            return None
        if save_path_pdg is not False:
            draw_pdg(dfg_nodes, attributes=True, save_path=save_path_pdg)
        for unknown in unknown_var:
            logging.warning('The variable ' + unknown.attributes['name'] + ' is not declared')
        if check_var:
            return unknown_var
        benchmarks['PDG'] = timeit.default_timer() - start
        micro_benchmark('Successfully produced the PDG in', timeit.default_timer() - start)
        if store_pdgs is not None:
            store_pdg = os.path.join(store_pdgs, os.path.basename(input_file.replace('.js', '.pickle')))
            # pickle.dump(dfg_nodes, open(store_pdg, 'wb'))
            # I don't know why, but some PDGs lead to Segfault, this way it does not kill the
            # current process at least
            p = Process(target=pickle_dump_process, args=(dfg_nodes, store_pdg))
            p.start()
            p.join()
            if p.exitcode != 0:
                logging.error('Something wrong occurred to pickle the PDG of %s', store_pdg)
                if os.path.isfile(store_pdg) and os.stat(store_pdg).st_size == 0:
                    os.remove(store_pdg)
        return dfg_nodes
    return None


def handle_one_pdg(root, js, pdg_store_dir):
    """ Stores the PDG of js located in root, in store_pdgs. """
    return get_data_flow(
        input_file=os.path.join(root, js), 
        benchmarks=dict(), 
        store_pdgs=pdg_store_dir
    )

def worker(input: Queue, output: Queue):
    """ Worker """
    while True:
        try:
            in_dir, js_relpath, out_dir = input.get(timeout=2)
            jstap_pdg = handle_one_pdg(in_dir, js_relpath, out_dir)
            if jstap_pdg is not None: output.put((js_relpath, jstap_pdg))
        except Exception:
            break
    pass

def __find_all_files(under: str, is_satisfied: Callable[[str], bool]) -> Generator[str, None, None]: 
    under = os.path.abspath(under)
    files, subdirs = set(), set()
    for sub in sorted(os.listdir(under)): 
        sub_dir = os.path.join(under, sub)
        if os.path.isfile(sub_dir): files.add(sub)
        if os.path.isdir(sub_dir): subdirs.add(sub_dir)
    for file in files: 
        if is_satisfied(file):  yield os.path.abspath(os.path.join(under, file))
    for sub_dir in subdirs: yield from __find_all_files(sub_dir, is_satisfied)        
    pass

def store_pdg_folder(input_dir: str, output_dir: Optional[str]=None) -> List[str]:
    """
        Stores the PDGs of the JS files from folder_js.

        -------
        Parameters:
        - folder_js: str
            Path of the folder containing the files to get the PDG of.
    """

    start = timeit.default_timer()
    ram = psutil.virtual_memory().used
    # benchmarks = dict()

    workers = list()
    jsfile_queue, pdg_queue = Queue(), Queue()

    if not os.path.exists(input_dir): 
        return logging.exception('The path %s does not exist', input_dir)
    
    if output_dir is not None: 
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)

    for fpath in __find_all_files(input_dir, lambda fn:fn.endswith('.js')): 
        jsfile_relpath = fpath.removeprefix(input_dir)
        jsfile_relpath = jsfile_relpath.removeprefix('/')
        gpfile_relpath = f"{jsfile_relpath.removesuffix('.js')}.pickle"
        if os.path.isfile(gpfile_relpath): continue
        jsfile_queue.put([input_dir, jsfile_relpath, output_dir]) # None means not output as a file.

    for i in range(NUM_WORKERS):
        p = Process(target=worker, args=(jsfile_queue, pdg_queue))
        p.start()
        print(f"Starting process {i}")
        workers.append(p)

    for w in workers: w.join()

    get_ram_usage(psutil.virtual_memory().used - ram)
    micro_benchmark('Total elapsed time:', timeit.default_timer() - start)
    def get_data(): 
        while not pdg_queue.empty(): yield pdg_queue.get_nowait() 
    return list(get_data())

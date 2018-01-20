# About fork!

It's my fork of plugin with tuning for my convenience of work. Generaly, i add "Feature Config", which allows you to enable and disable certain elements of the pop-out menus from Actions.py. I don't use central feature "Reconstruct type", but various auxiliary recasts functions is amazing. So, I added my own version of creating of type and virtual tables. In my variant, a simple structure of a certain size with fields of a given width is created. Further, the fields are detailed during analysis. Some works with "actions" was unified.

Port to IDA 7.0 save compatible with IDA 6.95. Port don't tested enough, but at first glance it works.

# About

Plugin assists in creation classes/structures and detection virtual tables. Also helps to transform decompiler output faster and allows to make some stuff otherwise impossible. Was introduced at ZeroNights 2016 ([slides][zeronights]).

# Installation

Just copy `HexRaysPyTools.py` file and `HexRaysPyTools` directory to Ida plugins directory

# Features

**[Recently added][feature_history]**

## 1) Structure Creation

Best to use with [Class Informer][0] plugin, because it helps to automatically get original names of the classes.

### Structure Builder (Alt + F8)

The place where all collected information about scanned variables can be viewed and modified. Two ways to collect information:
* Right Click on variable -> Scan Variable. Recognizes fields usage within current function
* Right Click on variable -> Deep Scan Variable. First recursively touches functions to make Ida recognize proper arguments (it happens only once for each function during session). Than recursively applies scanner to variables and functions that get our structure pointer as argument.

![img][builder]

* Types with __BOLD__ font are virtual tables. Double click opens list with all virtual functions that helps to visit them. Visited functions are marked with cross and color:

![img][virtual_functions]

* Types with _ITALIC_ font have been found as `void *` arguments and are not used in shape recognition.
* Double click on Field's names to edit
* Double click on offset opens window with every places where this type has been extracted. Click "Ok" button to open selected place in pseudocode window:

![img][scanned_variables]

__Finalize__ - opens window with editable C-like declaration and assigns new type to all scanned variables.

__Disable__, __Enable__ - are used for collision resolution.

__Origin__ - switches base from which offset to produce new fields to structure (this value will be added to every offset of new scanned variable).

__Array__ - makes selected field as array, the size of which is calculated automatically.

__Pack__ - creates and substitutes substructure for selected items (collisions for this items should be resolved).

__Unpack__ - dismembers selected structure and adds all it's fields to builder

__Remove__ - removes information about selected fields.

__Clear__ - clears everything.

__Recognize Shape__ - looks for appropriate structure for selected fields.

### Currently recognized access to fields

LEGAL_TYPES = { DWORD, QWORD, DWORD *, QWORD *, void * } - if variable's type is one of this types or is derivate from them, then it can be scanned by Right-Click-> Scan Variable. Also possible to scan pointers to structures if structure is just typedef like (`typedef StructureName;`). It can happen when binary has symbol information.

Abbreviations:
* var - variable
* obj - any object, including Virtual Table, that will be handled specially
* x - offset
* TYPE - simple (char, byte, float, ...) or complicated type not from LEGAL_TYPES
* XWORD - DWORD or QWORD
* PXWORD - DWORD * or QWORD *
* PVOID - void *, PVOID

| Variable type | Situation | Type | Offset |
| --- | --- | --- | --- |
| `XWORD` | `*(XWORD *) (var + x) = obj`| `typeof(obj) *` | `x` |
| `XWORD` | `*(XWORD *) (var + x) = &obj`| `typeof(obj) *` | `x` |
| `XWORD` | `*(TYPE *) (var + x)`| `TYPE` | `x` |
| `XWORD` | `function(... , (LEGAL_TYPE) (var + x), ...)` | _BYTE[]_ and recursion started for this function and argument index | `x` |
| `XWORD` | `function(... , (TYPE) (var + x), ...)`| argument's type | `x` |
| `XWORD` | `function(... , var + x, ...)`| argument's type | `x` |
| `XWORD *`, `PVOID` | `*var = obj` | `typeof(obj) *` | `0` |
| `XWORD *`, `PVOID` | `*var = &obj` | `typeof(obj) *` | `0` |
| `XWORD *`, `PVOID`| `*var = ???` | `XWORD` | `0` |
| `XWORD *` | `var[idx] = obj` |` typeof(obj) * ` | `idx * sizeof(XWORD)` |
| `XWORD *` | `var[idx] = &obj` |` typeof(obj) * ` | `idx * sizeof(XWORD)` |
| `XWORD *` | `var[idx] = ???` |` XWORD ` | `idx * sizeof(XWORD)` |
| `XWORD *`, `PVOID` | `*((TYPE *) var + x)`| `TYPE` | `x * sizeof(TYPE)` |
| `XWORD *`, `PVOID` | `function(... , (LEGAL_TYPE) (var + x), ...)` | _BYTE[]_ and recursion started for this function and argument index | `x * sizeof(XWORD)` |
| `XWORD *`, `PVOID` | `function(... , (TYPE) (var + x), ...)`| argument's type | `x * sizeof(XWORD)` |
| `PVOID` | `function(... , (TYPE *)var + x, ...)`| argument's type | `x * sizeof(TYPE)` |
| `PVOID` | `function(... , (TYPE)var + x, ...)`| argument's type | `x` |
| `PVOID` | `(TYPE *) ((char *)var + x)`| TYPE | `x` |

### Classes (Alt + F1)

Also can be found at _View->Open Subview->Classes_. Helps to manage classes (structures with virtual tables).

![img][classes]

##### !! Better to rename all functions before debugging because Ida can mess up with default names and information in virtual tables will be inconsistent
Class, virtual table and functions names are editable. Also function's declaration can be edited. After edit, altered items change font to _italic_. Right click opens following menu options:

* Expand All / Collapse All
* Refresh - clear all and rescan local types for information again
* Rollback - undo changes
* Commit - apply changes. Functions will be renamed and recasted both in virtual tables in Local Types and disassembly code.
* Set First Argument type - allows selecting first argument for function among all classes. If right click was used on class name, than its type will be automatically applied to virtual table at offset 0

You can also filter classes using Regexp either by class_name or by existence of specific functions. Just input expression in line edit for filtering by class_name or prepend it with "!" to filter by function name.

## 2) Disassembler code manipulations

### Structures with given size

Usage:

1. In Pseudocode viewer ight click on number -> "Structures with this size". (hotkey W)
2. Select library in which find structures
3. Select structure. Number will become `sizeof(Structure Name)` and type will be imported to Local Types

### Recognition of structures by shapes

Helps to find suitable structure by information gleaned from pseudocode after variable scanning.

Usage:

* _Method 1_
    1. Right click on variable with LEGAL_TYPE (See structure builder) -> Select "Recognize Shape".
    2. Select structure.
    3. Type of variable will be changed automatically.
* _Method 2_
    1. Clear Structure Builder if it's currently used.
    2. Right click on variables supposed to be the same -> "Scan Variable".
    3. Edit types (will be implemented later), disable or remove uninteresting fields and click button "Recognize Shape".
    4. You can selected several fields and try to recognize shape for them. If found and selected, they will be replaced by new structure.
    5. After final structure selection, types of all scanned variables will be changed automatically.

### Containing structures

Helps to find containing structure and makes code look pretty by replacing pointers with [CONTAINING_RECORD][1] macro

__Before:__

![img][bad_structures]

__After:__

![img][good_structures]

Usage:

If variable is a structure pointer and is used to address outside of its boundaries than:

1. Right click -> Select Containing Structure
2. Select Type Library
3. Select appropriate Structure and Offset
4. If result is disappointing then Right Click -> Reset Containing Structure and go to step 1

### Function signature manipulation

1. Right click on first line -> "Remove Return" converts return type to void (or from void to _DWORD)
2. Right click on argument -> "Remove Argument" disposes of this argument
3. Right click on convention -> "Convert to __usercall" switches to __usercall or __userpurge (same as __usercall but the callee cleans the stack)


### Recasting (Shift+R, Shift+L), Renaming (Shift+N, Ctrl+Shift+N)

Expressions from the table can be quickly modified. Select cast item or variable and press hotkey or select from Right-Click Menu Recast Variable, Return or Argument. It can be applied to both local and global variables.

| Original | Shift+L | Shift+R
| --- | --- | --- |
| var = (TYPE) expr | var type -> TYPE  |  |
| exp = (TYPE) var |  | var type -> TYPE |
| function(..., (TYPE) var, ...) | functions' argument -> TYPE | var type -> TYPE |
| (TYPE) function(...) | | functions' return type -> TYPE |
| return (TYPE) var | functions' return type -> TYPE | var type -> TYPE |
| struct.field = (TYPE) var | type(field) -> TYPE | |
| pstruct->field = (TYPE) var | type(field) -> TYPE | |

When you have an expression like `function(..., some_good_name, ...)`, you can rename function argument.

When you have an expression like `function(..., v12, ...)` and function has a nice name of the argument. You can quickly apply this name to the variable.

Also possible to rename `vXX = v_named` into `_v_named = v_named` and vice versa.

### Untangling 'if' statements

* By clicking on `if` manually allows to switch `then` and `else` branches
* Automatically applies following transformations:

Before:

```c
...
if (condition) {
    statement_1;
    statement_2;
    ...
    return another_value;
}
return value;
```

After:
```c
...
if (opposite_condition) {
    return value;
}
statement_1;
statement_2;
...
return another_value;            // if 'then' branch have no return, than `return value;`
```

## Other

### Structure Graph

Shows relationship between structures:

![img][structure_graph]

Also: dark green node is union, light green - enum.

Usage:

1. Open Local Types
2. Select interesting structures and right click -> "Show Graph" (Hotkey G)
3. Plugin creates a graph of all structures that have relationship with selected items.
4. Double clicking on node recalculates graph for it
5. Every node have a hint message that shows C-like typedef


[0]: https://sourceforge.net/projects/classinformer/
[1]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff542043%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
[zeronights]: zeronights_2016.pptx
[structure_graph]: Img/structure_builder.JPG
[bad_structures]: Img/bad.JPG
[good_structures]: Img/good.JPG
[builder]: Img/builder.JPG
[virtual_functions]: Img/virtual_functions.JPG
[scanned_variables]: Img/fields_xref.JPG
[classes]: Img/classes.JPG
[feature_history]: https://github.com/igogo-x86/HexRaysPyTools/wiki/History

# About

Plugin assist in creation classes/structures and detection virtual tables. Best to use with [Class Informer][0] plugin, because it helps to automatically get original classes names

# Features

### 1) Structure Graph

Shows relationship between structures.
![img][structure_graph]

Also: dark green node is union, light green - enum.
 
Usage:

1. Open Local Types
2. Select interesting structures and right click -> "Show Graph" (Hotkey G)
3. Plugin creates a graph of all structures that have relationship with selected items.
4. Double clicking on node recalculates graph for it
5. Every node have a hint message that shows C-like typedef

### 2) Structures with given size

Usage:

1. In Pseudocode viewer ight click on number -> "Structures with this size". (hotkey W)
2. Select library in which find structures
3. Select structure. Number will become `sizeof(Structure Name)` and type will be imported to Local Types

### 3) Recogition of structures by shapes

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
    4. You can selected several fields and try to recognize shpare for them. If found and selected, they will be replaced by new structure.
    5. After final structure selection, types of all scanned variables will be changed automatically.

### 4) Containing structures

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
4. If result is disapointing then Right Click -> Reset Containing Structure and go to step 1

### 5) Structure Builder (Alt + F8)

The place where all collected information about scanned variables can be viewed and modified

![img][builder]

* Types with __BOLD__ font are virtual tables. Double click opens list with all virtual functions that helps to visit them. Visited functions marked with cross and color.

![img][virtual_functions]

* Types with _ITALIC_ font are got as `void *` arguments and are not used in shape recognition.

* Field's names are editable by double click

__Finalize__ - opens window with editable C-like declaration and assigns new type to all scanned variabled.

__Disable__, __Enable__ - used for collision resoliution.

__Origin__ - switches base from which offset to produce new fields to structure (this value will be added to every offset of new scanned variable).

__Array__ - makes selected field as array, the size of which is calculated automatically.

__Pack__ - creates and substitutes substructure for selected items (collisions for this items should be resolved).

__Remove__ - removes information about selected fields.

__Clear__ - clears everything.

__Scanned Variables__ - do nothing.

__Recognize Shape__ - looks for appropriate structure for selected fields.

### Currently recognized access to fields

LEGAL_TYPES = { int, __int64, signed __int64 } - currently scannable variables

Abbreviations:
* var - variable
* obj - any object, including Virtual Table, that will be handled specially
* x - offset
* TYPE - char, _BYTE, int, _DWORD, float, double, etc

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

### 6) Function signature manipulation

1. Right click on first line -> "Remove Return" converts return type to void
2. Right click on argument -> "Remove Argument" disposes of this argument
3. Right click on convention -> "Convert to __usercall" switches to __usercall or __userpurge (same as __usercall but the callee cleans the stack)

[0]: https://sourceforge.net/projects/classinformer/
[1]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff542043%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
[structure_graph]: Img/structure_builder.JPG
[bad_structures]: Img/bad.JPG
[good_structures]: Img/good.JPG
[builder]: Img/builder.JPG
[virtual_functions]: Img/virtual_functions.JPG

### 7) Recast Item (Shift+R)

If you have instruction like this: `v1 = (TYPE) expr;` than Right click -> "Recast Item" menu changes type of v1 to final type of expr. expr can be either variable or expression of any complexity.
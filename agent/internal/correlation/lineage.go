package correlation

import "exionis/internal/process"

func buildGenealogyChain(pid uint32, imageName string, ppid uint32) (parentImg, grandParentImg, chain string, depth int, rootPID uint32) {
	tableMu.RLock()
	defer tableMu.RUnlock()

	parentImg = ""
	grandParentImg = ""
	chain = imageName
	depth = 1
	rootPID = pid

	if ppid > 0 {
		if parent, ok := processTable[ppid]; ok {
			parentImg = parent.Image
			chain = parent.Image + " > " + imageName
			depth = 2
			rootPID = parent.RootPID
			if rootPID == 0 {
				rootPID = parent.PID
			}

			if parent.PPID > 0 {
				if grandparent, ok := processTable[parent.PPID]; ok {
					grandParentImg = grandparent.Image
					chain = grandparent.Image + " > " + chain
					depth = 3
					if grandparent.RootPID != 0 {
						rootPID = grandparent.RootPID
					}
				}
			}
		}
	}

	if parentImg == "" && ppid > 0 {
		if name := process.GetProcessNameByPID(ppid); name != "" {
			parentImg = name
			chain = name + " > " + imageName
			depth = 2
		}
	}

	return parentImg, grandParentImg, chain, depth, rootPID
}

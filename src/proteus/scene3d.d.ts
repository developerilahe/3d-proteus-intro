export interface ProjectedCoord {
  x: number;
  y: number;
  visible: boolean;
}

export interface ProteusScene3DOptions {
  initialStep?: number;
  onSelectNode?: (nodeId: string) => void;
  onFrameProject?: (
    nodeCoords: Record<string, ProjectedCoord>,
    packetCoords: Record<string, ProjectedCoord>
  ) => void;
}

export interface ProteusScene3DHandle {
  setStep: (index: number, focusCamera?: boolean) => void;
  playScrollEntrance: (stepIndex?: number) => void;
  dispose: () => void;
}

export function createProteusScene3D(
  mountEl: HTMLElement,
  options?: ProteusScene3DOptions
): ProteusScene3DHandle;

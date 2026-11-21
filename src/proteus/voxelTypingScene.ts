import * as THREE from 'three';

// Pre-allocated scratch helpers (zero-GC in animation loop)
const _vA = new THREE.Vector3();

const PALETTE = {
  bg: 0x0d0d0d,
  face: 0xf3f4f8,
  extrudeTop: 0x4246ce,
  extrudeBottom: 0x1b1e63,
  cursor: 0x3fd1cb,
};

const FONT_SPEC = '700 172px "Poppins", "Inter", system-ui, sans-serif';
const WORLD_PER_PX = 1 / 26;
const EXTRUDE_LAYERS = 6;
const EXTRUDE_STEP_Z = 0.15;

function detectSoftwareWebGL(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return true;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
    const gpu = String(gl.getParameter(param) || '');
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
  } catch {
    return true;
  }
}

/**
 * Restrained architectural ease-out with tiny 2.5% micro-settle.
 */
function smoothSettle(t: number): number {
  if (t <= 0) return 0;
  if (t >= 1) return 1;
  const inv = 1 - t;
  const base = 1 - inv * inv * inv;
  const settle = Math.sin(t * Math.PI) * 0.028 * inv;
  return base + settle;
}

interface GlyphAsset {
  texture: THREE.CanvasTexture | null;
  planeW: number;
  planeH: number;
  advance: number;
  isSpace: boolean;
}

let sharedMeasureCtx: CanvasRenderingContext2D | null = null;
function getMeasureCtx(): CanvasRenderingContext2D | null {
  if (sharedMeasureCtx) return sharedMeasureCtx;
  const c = document.createElement('canvas');
  c.width = 64;
  c.height = 64;
  sharedMeasureCtx = c.getContext('2d');
  return sharedMeasureCtx;
}

function measureKernedAdvance(prevChar: string | null, ch: string): number {
  const ctx = getMeasureCtx();
  if (!ctx) return ch === ' ' ? 1.8 : 4.2;
  ctx.font = FONT_SPEC;
  if (!prevChar || prevChar === '\n' || prevChar === ' ') {
    return ctx.measureText(ch).width * WORLD_PER_PX;
  }
  const pairW = ctx.measureText(prevChar + ch).width;
  const prevW = ctx.measureText(prevChar).width;
  return Math.max(0.8, (pairW - prevW) * WORLD_PER_PX);
}

const glyphAssetCache = new Map<string, GlyphAsset>();

function createGlyphAsset(ch: string, maxAnisotropy: number): GlyphAsset {
  const cached = glyphAssetCache.get(ch);
  if (cached) return cached;

  if (ch === ' ') {
    const advance = measureKernedAdvance(null, ' ');
    const spaceAsset: GlyphAsset = {
      texture: null,
      planeW: 0,
      planeH: 0,
      advance,
      isSpace: true,
    };
    glyphAssetCache.set(ch, spaceAsset);
    return spaceAsset;
  }

  const canvasW = 320;
  const canvasH = 320;
  const canvas = document.createElement('canvas');
  canvas.width = canvasW;
  canvas.height = canvasH;
  const ctx = canvas.getContext('2d');

  if (!ctx) {
    return {
      texture: null,
      planeW: 4,
      planeH: 4,
      advance: 4,
      isSpace: true,
    };
  }

  ctx.clearRect(0, 0, canvasW, canvasH);
  ctx.font = FONT_SPEC;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#ffffff';
  ctx.fillText(ch, canvasW * 0.5, canvasH * 0.52);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = maxAnisotropy;
  texture.minFilter = THREE.LinearMipmapLinearFilter;
  texture.magFilter = THREE.LinearFilter;
  texture.needsUpdate = true;

  const advance = measureKernedAdvance(null, ch);
  const asset: GlyphAsset = {
    texture,
    planeW: canvasW * WORLD_PER_PX,
    planeH: canvasH * WORLD_PER_PX,
    advance,
    isSpace: false,
  };
  glyphAssetCache.set(ch, asset);
  return asset;
}

interface LetterActor {
  id: number;
  char: string;
  group: THREE.Group | null;
  frontMat: THREE.MeshBasicMaterial | null;
  extrudeMats: THREE.MeshBasicMaterial[];
  advance: number;
  targetX: number;
  targetY: number;
  progress: number;
  exiting: boolean;
  isNewline: boolean;
  tiltX: number;
  tiltY: number;
}

export interface KineticTypingHandle {
  setText: (text: string) => void;
  refreshFont: () => void;
  dispose: () => void;
}

export function createVoxelTypingScene(
  mountEl: HTMLElement,
  initialText = ''
): KineticTypingHandle {
  const isSoftwareGl = detectSoftwareWebGL();
  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(PALETTE.bg);
  scene.fog = new THREE.FogExp2(PALETTE.bg, 0.006);

  let viewportW = Math.max(320, mountEl.clientWidth || 1280);
  let viewportH = Math.max(320, mountEl.clientHeight || 720);

  const camera = new THREE.PerspectiveCamera(38, viewportW / viewportH, 0.1, 350);
  camera.position.set(0, 0, 56);

  const renderer = new THREE.WebGLRenderer({
    antialias: !isSoftwareGl,
    powerPreference: 'high-performance',
  });
  renderer.setSize(viewportW, viewportH);
  renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;
  renderer.domElement.style.display = 'block';
  renderer.domElement.style.width = '100%';
  renderer.domElement.style.height = '100%';
  mountEl.appendChild(renderer.domElement);

  const maxAnisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy());
  const sharedPlaneGeo = new THREE.PlaneGeometry(1, 1);

  // Subtle architectural floor plane + grid for spatial grounding
  const gridHelper = new THREE.GridHelper(220, 44, 0x2f2b28, 0x181615);
  gridHelper.position.set(0, -14.5, -10);
  scene.add(gridHelper);

  // Minimal deep-field indigo accent horizon line
  const lineGeo = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(-90, -14.48, -10),
    new THREE.Vector3(90, -14.48, -10),
  ]);
  const lineMat = new THREE.LineBasicMaterial({
    color: PALETTE.extrudeTop,
    transparent: true,
    opacity: 0.35,
  });
  const horizonLine = new THREE.Line(lineGeo, lineMat);
  scene.add(horizonLine);

  const textGroup = new THREE.Group();
  scene.add(textGroup);

  // Sleek #3FD1CB 3D Vertical Cursor Bar
  const cursorGeo = new THREE.BoxGeometry(0.32, 5.4, 0.85);
  const cursorMat = new THREE.MeshBasicMaterial({
    color: PALETTE.cursor,
    transparent: true,
    opacity: 0.92,
  });
  const cursorMesh = new THREE.Mesh(cursorGeo, cursorMat);
  cursorMesh.position.set(0, 0, 0.25);
  textGroup.add(cursorMesh);

  let nextActorId = 1;
  let activeText = '';
  let activeActors: LetterActor[] = [];
  const exitingActors: LetterActor[] = [];

  let targetCamX = 0;
  let targetCamY = 0;
  let targetGroupZ = 0;
  let cursorTargetX = 0;
  let cursorTargetY = 0;

  const extrudeColorTop = new THREE.Color(PALETTE.extrudeTop);
  const extrudeColorBottom = new THREE.Color(PALETTE.extrudeBottom);

  function buildLetterActor(ch: string, prevChar: string | null): LetterActor {
    const id = nextActorId++;
    if (ch === '\n' || ch === '\r') {
      return {
        id,
        char: ch,
        group: null,
        frontMat: null,
        extrudeMats: [],
        advance: 0,
        targetX: 0,
        targetY: 0,
        progress: 1,
        exiting: false,
        isNewline: true,
        tiltX: 0,
        tiltY: 0,
      };
    }

    const asset = createGlyphAsset(ch, maxAnisotropy);
    const kernedAdvance = measureKernedAdvance(prevChar, ch);

    if (asset.isSpace || !asset.texture) {
      return {
        id,
        char: ch,
        group: null,
        frontMat: null,
        extrudeMats: [],
        advance: kernedAdvance,
        targetX: 0,
        targetY: 0,
        progress: 1,
        exiting: false,
        isNewline: false,
        tiltX: 0,
        tiltY: 0,
      };
    }

    const group = new THREE.Group();
    const extrudeMats: THREE.MeshBasicMaterial[] = [];

    // Cobalt #4246ce -> #1b1e63 3D Z-extrusion stack behind crisp white Poppins glyph
    for (let i = EXTRUDE_LAYERS; i >= 1; i--) {
      const ratio = i / EXTRUDE_LAYERS;
      const col = extrudeColorTop.clone().lerp(extrudeColorBottom, ratio);
      const eMat = new THREE.MeshBasicMaterial({
        map: asset.texture,
        color: col,
        alphaTest: 0.36,
        transparent: false,
        side: THREE.DoubleSide,
      });
      const eMesh = new THREE.Mesh(sharedPlaneGeo, eMat);
      eMesh.scale.set(asset.planeW, asset.planeH, 1);
      eMesh.position.z = -i * EXTRUDE_STEP_Z;
      group.add(eMesh);
      extrudeMats.push(eMat);
    }

    // Razor-sharp front glyph face
    const frontMat = new THREE.MeshBasicMaterial({
      map: asset.texture,
      color: PALETTE.face,
      transparent: true,
      depthWrite: false,
      alphaTest: 0.01,
      opacity: prefersReducedMotion ? 1 : 0,
    });
    const frontMesh = new THREE.Mesh(sharedPlaneGeo, frontMat);
    frontMesh.scale.set(asset.planeW, asset.planeH, 1);
    frontMesh.position.z = 0.02;
    frontMesh.renderOrder = 2;
    group.add(frontMesh);

    if (!prefersReducedMotion) {
      group.position.z = 36;
      group.scale.setScalar(0.82);
    }
    textGroup.add(group);

    return {
      id,
      char: ch,
      group,
      frontMat,
      extrudeMats,
      advance: kernedAdvance,
      targetX: 0,
      targetY: 0,
      progress: prefersReducedMotion ? 1 : 0,
      exiting: false,
      isNewline: false,
      tiltX: -0.14,
      tiltY: 0.28,
    };
  }

  function layoutActors() {
    // Split into lines so each line is horizontally centered
    const lines: LetterActor[][] = [[]];
    for (const actor of activeActors) {
      if (actor.isNewline) {
        lines.push([]);
      } else {
        lines[lines.length - 1].push(actor);
      }
    }

    const lineHeight = 7.4;
    const totalLines = lines.length;
    const startY = ((totalLines - 1) * lineHeight) * 0.5 + 0.8;

    let maxLineWidth = 0;

    for (let li = 0; li < totalLines; li++) {
      const line = lines[li];
      let lineWidth = 0;
      for (const a of line) {
        lineWidth += a.advance;
      }
      maxLineWidth = Math.max(maxLineWidth, lineWidth);

      let cursorX = -lineWidth * 0.5;
      const lineY = startY - li * lineHeight;

      for (const a of line) {
        const centerX = cursorX + a.advance * 0.5;
        a.targetX = centerX;
        a.targetY = lineY;
        if (a.group && a.progress === 0 && a.group.position.x === 0 && a.group.position.y === 0) {
          a.group.position.x = centerX;
          a.group.position.y = lineY;
        }
        cursorX += a.advance;
      }

      if (li === totalLines - 1) {
        cursorTargetX = cursorX + 0.55;
        cursorTargetY = lineY;
      }
    }

    if (activeActors.length === 0) {
      cursorTargetX = 0;
      cursorTargetY = 0.8;
    }

    // Fit camera distance cleanly to the widest line across desktop & mobile
    const aspect = Math.max(0.5, viewportW / Math.max(1, viewportH));
    const fovRad = THREE.MathUtils.degToRad(camera.fov * 0.5);
    const desiredSpan = Math.max(24, maxLineWidth + 10);
    const neededDist = (desiredSpan * 0.52) / Math.max(0.24, Math.tan(fovRad) * aspect);
    targetGroupZ = Math.min(6, 56 - Math.max(52, neededDist));
  }

  function retireActor(actor: LetterActor) {
    if (!actor.group) return;
    actor.exiting = true;
    actor.progress = 0;
    exitingActors.push(actor);
  }

  function setText(nextRaw: string) {
    const next = (nextRaw || '').slice(0, 48);
    if (next === activeText) return;

    const oldActors = activeActors;
    const newActors: LetterActor[] = [];
    const maxLen = Math.max(oldActors.length, next.length);

    let prevChar: string | null = null;
    for (let i = 0; i < maxLen; i++) {
      const oldA = oldActors[i];
      const nextCh = next[i];
      if (oldA && oldA.char === nextCh) {
        newActors.push(oldA);
        prevChar = nextCh;
      } else {
        if (oldA) {
          retireActor(oldA);
        }
        if (nextCh !== undefined) {
          newActors.push(buildLetterActor(nextCh, prevChar));
          prevChar = nextCh;
        }
      }
    }

    activeActors = newActors;
    activeText = next;
    layoutActors();
  }

  function refreshFont() {
    for (const asset of glyphAssetCache.values()) {
      asset.texture?.dispose();
    }
    glyphAssetCache.clear();

    const prev = activeText;
    for (const a of activeActors) {
      if (a.group) {
        textGroup.remove(a.group);
        a.frontMat?.dispose();
        for (const m of a.extrudeMats) m.dispose();
      }
    }
    activeActors = [];
    activeText = '';
    if (prev) {
      // Rebuild instantaneously in place without re-flying in if already displayed
      let prevChar: string | null = null;
      const rebuilt: LetterActor[] = [];
      for (const ch of prev) {
        const actor = buildLetterActor(ch, prevChar);
        actor.progress = 1;
        if (actor.group && actor.frontMat) {
          actor.group.position.z = 0;
          actor.group.scale.setScalar(1);
          actor.group.rotation.set(0, 0, 0);
          actor.frontMat.opacity = 1;
        }
        rebuilt.push(actor);
        prevChar = ch;
      }
      activeActors = rebuilt;
      activeText = prev;
      layoutActors();
      for (const a of activeActors) {
        if (a.group) {
          a.group.position.x = a.targetX;
          a.group.position.y = a.targetY;
        }
      }
    }
  }

  if (initialText) {
    setText(initialText);
  }

  function onPointerMove(e: PointerEvent) {
    const rect = renderer.domElement.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const nx = (e.clientX - rect.left) / rect.width - 0.5;
    const ny = (e.clientY - rect.top) / rect.height - 0.5;
    targetCamX = nx * 6.5;
    targetCamY = -ny * 3.8;
  }

  function onPointerLeave() {
    targetCamX = 0;
    targetCamY = 0;
  }

  mountEl.addEventListener('pointermove', onPointerMove);
  mountEl.addEventListener('pointerleave', onPointerLeave);

  let disposed = false;
  let frameId = 0;
  let isVisible = true;
  let elapsedTotal = 0;
  const clock = new THREE.Clock();

  function afterDraw(cb: () => void) {
    if (disposed) return;
    const gl = renderer.getContext() as WebGL2RenderingContext;
    const sync = gl && gl.fenceSync ? gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0) : null;
    if (sync && gl.flush) {
      gl.flush();
      const poll = () => {
        if (disposed) return;
        const status = gl.getSyncParameter(sync, gl.SYNC_STATUS);
        if (status === gl.UNSIGNALED) frameId = window.setTimeout(poll, 4);
        else {
          gl.deleteSync(sync);
          frameId = window.setTimeout(cb, 16);
        }
      };
      frameId = window.setTimeout(poll, 4);
    } else {
      frameId = window.setTimeout(cb, 20);
    }
  }

  function tick() {
    if (disposed) return;
    const dt = Math.min(0.033, clock.getDelta());
    elapsedTotal += dt;

    // Subtle pointer camera parallax revealing cobalt 3D letter extrusion
    camera.position.x = THREE.MathUtils.damp(camera.position.x, targetCamX, 5.5, dt);
    camera.position.y = THREE.MathUtils.damp(camera.position.y, targetCamY, 5.5, dt);
    _vA.set(0, 0, 0);
    camera.lookAt(_vA);

    textGroup.position.z = THREE.MathUtils.damp(textGroup.position.z, targetGroupZ, 6.2, dt);

    // Update active glyphs
    for (const actor of activeActors) {
      if (!actor.group) continue;
      actor.group.position.x = THREE.MathUtils.damp(actor.group.position.x, actor.targetX, 15, dt);
      actor.group.position.y = THREE.MathUtils.damp(actor.group.position.y, actor.targetY, 15, dt);

      if (actor.progress < 1) {
        actor.progress = Math.min(1, actor.progress + dt * 2.9);
        const eased = smoothSettle(actor.progress);
        actor.group.position.z = (1 - eased) * 24;
        actor.group.rotation.x = (1 - eased) * actor.tiltX;
        actor.group.rotation.y = (1 - eased) * actor.tiltY;
        actor.group.scale.setScalar(0.86 + eased * 0.14);
        if (actor.frontMat) {
          actor.frontMat.opacity = Math.min(1, actor.progress * 2.1);
        }
      } else {
        actor.group.position.z = 0;
        actor.group.rotation.set(0, 0, 0);
        actor.group.scale.setScalar(1);
        if (actor.frontMat) actor.frontMat.opacity = 1;
      }
    }

    // Update deleting glyphs sweeping cleanly into depth
    for (let i = exitingActors.length - 1; i >= 0; i--) {
      const actor = exitingActors[i];
      if (!actor.group) {
        exitingActors.splice(i, 1);
        continue;
      }
      actor.progress = Math.min(1, actor.progress + dt * 4.2);
      const easeIn = actor.progress * actor.progress;
      actor.group.position.z = -easeIn * 36;
      actor.group.rotation.x = easeIn * actor.tiltX * 1.5;
      actor.group.rotation.y = easeIn * actor.tiltY * 1.5;
      actor.group.scale.setScalar(Math.max(0.05, 1 - easeIn * 0.65));
      if (actor.frontMat) {
        actor.frontMat.opacity = Math.max(0, 1 - actor.progress * 1.3);
      }

      if (actor.progress >= 1) {
        textGroup.remove(actor.group);
        actor.frontMat?.dispose();
        for (const m of actor.extrudeMats) m.dispose();
        exitingActors.splice(i, 1);
      }
    }

    // Smooth cursor tracking & crisp blink
    cursorMesh.position.x = THREE.MathUtils.damp(cursorMesh.position.x, cursorTargetX, 18, dt);
    cursorMesh.position.y = THREE.MathUtils.damp(cursorMesh.position.y, cursorTargetY, 18, dt);
    cursorMesh.visible = Math.floor(elapsedTotal * 2.2) % 2 === 0;

    if (isVisible) {
      renderer.render(scene, camera);
      if (isSoftwareGl) {
        afterDraw(() => {
          if (!disposed) tick();
        });
      } else {
        frameId = requestAnimationFrame(tick);
      }
    }
  }

  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      viewportW = Math.max(320, Math.floor(entry.contentRect.width));
      viewportH = Math.max(320, Math.floor(entry.contentRect.height));
      camera.aspect = viewportW / viewportH;
      camera.updateProjectionMatrix();
      renderer.setSize(viewportW, viewportH);
      layoutActors();
    }
  });
  resizeObserver.observe(mountEl);

  const intersectionObserver = new IntersectionObserver((entries) => {
    const nextVisible = entries[0]?.isIntersecting ?? true;
    const wasPaused = !isVisible && nextVisible;
    isVisible = nextVisible;
    if (wasPaused && !disposed) {
      clock.getDelta();
      tick();
    }
  });
  intersectionObserver.observe(mountEl);

  // Pre-warm glyph textures for marketing headline characters to eliminate mid-animation hitches
  for (const ch of 'PROTEUSLWHILEMONIRCAGBFAVYD. ') {
    createGlyphAsset(ch, maxAnisotropy);
  }

  if (!isSoftwareGl) renderer.compile(scene, camera);
  tick();

  return {
    setText,
    refreshFont,
    dispose() {
      disposed = true;
      cancelAnimationFrame(frameId);
      clearTimeout(frameId);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      mountEl.removeEventListener('pointermove', onPointerMove);
      mountEl.removeEventListener('pointerleave', onPointerLeave);

      for (const a of activeActors) {
        a.frontMat?.dispose();
        for (const m of a.extrudeMats) m.dispose();
      }
      for (const a of exitingActors) {
        a.frontMat?.dispose();
        for (const m of a.extrudeMats) m.dispose();
      }
      for (const asset of glyphAssetCache.values()) {
        asset.texture?.dispose();
      }
      glyphAssetCache.clear();

      sharedPlaneGeo.dispose();
      cursorGeo.dispose();
      cursorMat.dispose();
      lineGeo.dispose();
      lineMat.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === mountEl) {
        mountEl.removeChild(renderer.domElement);
      }
    },
  };
}

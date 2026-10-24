import React, { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * ThreeMultiverseScene
 * Real browser-rendered WebGL 3D scene with Three.js.
 * Features:
 *  - 3D cosmic dust / floating particles with theme colors (cyan, orange, purple)
 *  - Rotating 3D wireframe energy rings (gyroscopic toruses)
 *  - Interactive mouse parallax & camera perspective tilt
 *  - Clean resource disposal on unmount
 *  - Gracefully respects prefers-reduced-motion
 */
export default function ThreeMultiverseScene({ className = '' }) {
  const mountRef = useRef(null)

  useEffect(() => {
    const container = mountRef.current
    if (!container) return

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

    let animationFrameId
    let width = container.clientWidth || window.innerWidth
    let height = container.clientHeight || window.innerHeight

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 1000)
    camera.position.z = 6

    let renderer
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' })
      renderer.setSize(width, height)
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
      renderer.domElement.style.position = 'absolute'
      renderer.domElement.style.inset = '0'
      renderer.domElement.style.pointerEvents = 'none'
      container.appendChild(renderer.domElement)
    } catch (err) {
      console.warn('WebGL initialization failed, falling back to 2D:', err)
      return
    }

    // 2. 3D Cosmic Dust Particle Cloud
    const particleCount = 450
    const positions = new Float32Array(particleCount * 3)
    const colors = new Float32Array(particleCount * 3)

    const palette = [
      new THREE.Color('#22d3ee'), // cyan
      new THREE.Color('#f97316'), // orange
      new THREE.Color('#a855f7'), // purple
      new THREE.Color('#38bdf8'), // light blue
    ]

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3]     = (Math.random() - 0.5) * 22
      positions[i * 3 + 1] = (Math.random() - 0.5) * 16
      positions[i * 3 + 2] = (Math.random() - 0.5) * 14

      const color = palette[Math.floor(Math.random() * palette.length)]
      colors[i * 3]     = color.r
      colors[i * 3 + 1] = color.g
      colors[i * 3 + 2] = color.b
    }

    const particlesGeometry = new THREE.BufferGeometry()
    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    particlesGeometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))

    // Canvas circular particle texture
    const canvas = document.createElement('canvas')
    canvas.width = 32
    canvas.height = 32
    const ctx = canvas.getContext('2d')
    const gradient = ctx.createRadialGradient(16, 16, 0, 16, 16, 16)
    gradient.addColorStop(0, 'rgba(255,255,255,1)')
    gradient.addColorStop(0.3, 'rgba(255,255,255,0.7)')
    gradient.addColorStop(0.8, 'rgba(255,255,255,0.15)')
    gradient.addColorStop(1, 'rgba(255,255,255,0)')
    ctx.fillStyle = gradient
    ctx.fillRect(0, 0, 32, 32)
    const particleTexture = new THREE.CanvasTexture(canvas)

    const particlesMaterial = new THREE.PointsMaterial({
      size: 0.16,
      map: particleTexture,
      transparent: true,
      vertexColors: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
    const particleSystem = new THREE.Points(particlesGeometry, particlesMaterial)
    scene.add(particleSystem)

    // 3. 3D Gyroscopic Energy Rings for the 3 multiverse guardians
    // Center ring (Cyan sentinel)
    const centerTorusGeo = new THREE.TorusGeometry(1.6, 0.018, 16, 64)
    const centerTorusMat = new THREE.MeshBasicMaterial({
      color: 0x22d3ee,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    })
    const centerRing = new THREE.Mesh(centerTorusGeo, centerTorusMat)
    centerRing.position.set(0, 0.2, -1)
    scene.add(centerRing)

    // Left ring (Orange volt runner)
    const leftTorusGeo = new THREE.TorusGeometry(1.2, 0.015, 12, 48)
    const leftTorusMat = new THREE.MeshBasicMaterial({
      color: 0xf97316,
      wireframe: true,
      transparent: true,
      opacity: 0.28,
    })
    const leftRing = new THREE.Mesh(leftTorusGeo, leftTorusMat)
    leftRing.position.set(-3.2, 0.0, -1.8)
    scene.add(leftRing)

    // Right ring (Purple void architect)
    const rightTorusGeo = new THREE.TorusGeometry(1.3, 0.015, 12, 48)
    const rightTorusMat = new THREE.MeshBasicMaterial({
      color: 0xa855f7,
      wireframe: true,
      transparent: true,
      opacity: 0.28,
    })
    const rightRing = new THREE.Mesh(rightTorusGeo, rightTorusMat)
    rightRing.position.set(3.2, 0.0, -1.8)
    scene.add(rightRing)

    // 4. Mouse interaction
    let mouseX = 0
    let mouseY = 0
    let targetX = 0
    let targetY = 0

    const onMouseMove = (e) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2
    }
    window.addEventListener('mousemove', onMouseMove, { passive: true })

    // 5. Window resize handler
    const onResize = () => {
      if (!container) return
      width = container.clientWidth || window.innerWidth
      height = container.clientHeight || window.innerHeight
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      renderer.setSize(width, height)
    }
    window.addEventListener('resize', onResize)

    // 6. Animation loop
    let clock = new THREE.Clock()

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate)

      const delta = clock.getDelta()
      const speed = prefersReducedMotion ? 0.1 : 1.0

      // Smooth mouse follow
      targetX += (mouseX - targetX) * 0.05
      targetY += (mouseY - targetY) * 0.05

      camera.position.x = targetX * 0.8
      camera.position.y = -targetY * 0.5
      camera.lookAt(0, 0, 0)

      // Ring rotations
      centerRing.rotation.x += 0.25 * delta * speed
      centerRing.rotation.y += 0.35 * delta * speed
      centerRing.rotation.z += 0.15 * delta * speed

      leftRing.rotation.x += 0.3 * delta * speed
      leftRing.rotation.y -= 0.4 * delta * speed

      rightRing.rotation.x -= 0.35 * delta * speed
      rightRing.rotation.z += 0.25 * delta * speed

      // Particle system gentle drift
      particleSystem.rotation.y += 0.03 * delta * speed
      particleSystem.rotation.x = targetY * 0.1

      renderer.render(scene, camera)
    }

    animate()

    // 7. Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId)
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('resize', onResize)

      if (renderer && renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
      particlesGeometry.dispose()
      particlesMaterial.dispose()
      particleTexture.dispose()
      centerTorusGeo.dispose()
      centerTorusMat.dispose()
      leftTorusGeo.dispose()
      leftTorusMat.dispose()
      rightTorusGeo.dispose()
      rightTorusMat.dispose()
      renderer?.dispose()
    }
  }, [])

  return (
    <div
      ref={mountRef}
      className={className}
      style={{
        position: 'absolute',
        inset: 0,
        overflow: 'hidden',
        pointerEvents: 'none',
        zIndex: 1,
      }}
      aria-hidden="true"
    />
  )
}

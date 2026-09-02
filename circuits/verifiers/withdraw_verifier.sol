// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 17001673527606625723650251823261168129534784296517527218598607779373166088964;
    uint256 constant IC0y = 4909244048981224543416259842283632899485670009498650348602243586570784920185;
    
    uint256 constant IC1x = 14297772645059049121061813435470272138599879473696669343957135906473964255125;
    uint256 constant IC1y = 18306244669298483110007014598762550957976424316491262469959327355891629666170;
    
    uint256 constant IC2x = 8735431795095571342562876037783406766884141410582885584032302956583976613934;
    uint256 constant IC2y = 5867973023975053373746875770601016878078959952008658762237210419733065913718;
    
    uint256 constant IC3x = 15056145852111857652759075625195920739017006049693522640002623480437472290698;
    uint256 constant IC3y = 4650099897878911230782281682935198349171386696291252904487353565922421445107;
    
    uint256 constant IC4x = 20463133427665591005433956468983060133605990795115739092317229368362778292040;
    uint256 constant IC4y = 18701013745277422568771228152566661212246826612528601345378453541692213401978;
    
    uint256 constant IC5x = 473910982801405909262474451104364342695936032038564785097335074570029759117;
    uint256 constant IC5y = 8573398340666609291868347960190119336389424650928146559150359910761108093309;
    
    uint256 constant IC6x = 14568866955702966536486671021887879914380266871272783493080403003520634090902;
    uint256 constant IC6y = 5651262567199106910840203588365387448927726032287138956446486598130255593247;
    
    uint256 constant IC7x = 7858422536961121413233421637810170931373909387460961937535397799700788674496;
    uint256 constant IC7y = 9886231663942013396130689703243245778350622408047036392828848454675592164655;
    
    uint256 constant IC8x = 7328210720620351550576755011763018768005979582005265243960688810812272239851;
    uint256 constant IC8y = 3160333471333847558249591807049789969912604653356066245506372364063035138527;
    
    uint256 constant IC9x = 16210117469270012347407325848292892454985605571799444855029854192217704932611;
    uint256 constant IC9y = 867022340256590238330201646280077838365196608810799039534665194725348274976;
    
    uint256 constant IC10x = 3853937452725923911869654277206527946437161760068565864711256569332108615953;
    uint256 constant IC10y = 14380370411315751096468606753083935052154770822138801944435367252743660631172;
    
    uint256 constant IC11x = 10744636470772830896448180453352755627886450054198604650869489247001777517692;
    uint256 constant IC11y = 1441936301767528082031141738770394984057129576256486521781283838259716192614;
    
    uint256 constant IC12x = 13900316410701272126259888156102607172239416892386711860544962924519260506142;
    uint256 constant IC12y = 7760328860211674955180667381183202228626715627601036318887875874915102246799;
    
    uint256 constant IC13x = 14705452533870572562097477425167183844003495595945963898258031651827174454554;
    uint256 constant IC13y = 10143925931042113515781263992043070704571402710702332501796641462683701346076;
    
    uint256 constant IC14x = 14000139183562571310867967009903387863820842922854070494798594378575216502388;
    uint256 constant IC14y = 18698304555046608286731840251251853672581330242605367456954480834258640941003;
    
    uint256 constant IC15x = 17531168654378095158755935855080136894081485110873756769111449220131068613218;
    uint256 constant IC15y = 1005201415718062153561342563979564040581405141310844698493149280054251540398;
    
    uint256 constant IC16x = 1171747086442635295593082018586727144703946349894267572465024449565618663330;
    uint256 constant IC16y = 13720990729066702056417111309893228837256349956823954521983207107658308482928;
    
    uint256 constant IC17x = 14039619698871170843107050200579656372411122838192244976900814479490789662151;
    uint256 constant IC17y = 1532608797503281947462267665838069743732506204850277906023370834959603168458;
    
    uint256 constant IC18x = 3951919457687819163732753029890540587643371593065188020782536879343864665661;
    uint256 constant IC18y = 12709230678975351423193691059729180200330920865233161864522363102404752367623;
    
    uint256 constant IC19x = 10849572454553397186338429701352978614776149268584195765088737077253161311441;
    uint256 constant IC19y = 11526964298385950582461250191359578242110674920657356595244283024890970152398;
    
    uint256 constant IC20x = 10249350873551191254752670641147852710350535338282323639610530782698695117189;
    uint256 constant IC20y = 17493622558575632399998761934348154611194600782796626228558765873014924358490;
    
    uint256 constant IC21x = 12145550469864981068818886450116397304719021283216359893650072422015316750286;
    uint256 constant IC21y = 9300353637882822387804198104444055600041888645793059629732081744436985938748;
    
    uint256 constant IC22x = 10174330207648332181085787993622002530963642933026265718331454782720492983921;
    uint256 constant IC22y = 1510431916253675868301106933708276550159672885756132585273193888161016559292;
    
    uint256 constant IC23x = 16733107158543809727142502729401323151749488648334169438897348262310036865676;
    uint256 constant IC23y = 6018584172789962682363621069319197042925187696080233918517335253200275599681;
    
    uint256 constant IC24x = 18665215874505826215208681800765978988093426678913976087048395334866775961678;
    uint256 constant IC24y = 2271450562206529092505601969457738524150559338664754195573362967835084972414;
    
    uint256 constant IC25x = 12666832558610308024595566785160695090781187884654679811071531842465829377326;
    uint256 constant IC25y = 3180996981453894567603168202486516520913399194105102559811276534885445496087;
    
    uint256 constant IC26x = 14253822887673984102442744681143449031467174615993130435067098302310803917057;
    uint256 constant IC26y = 1443922914009564475095230770228349696122270285363263506655868903970880078187;
    
    uint256 constant IC27x = 1776008255743911496126503921550201098143704258319363752561891563533590378152;
    uint256 constant IC27y = 15434925504989819333701019508655302198767070369981619974904110201065565292537;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[27] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

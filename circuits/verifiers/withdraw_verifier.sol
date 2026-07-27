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

    
    uint256 constant IC0x = 21058313626428724049559636023623151455775821641024130943568352749152599778695;
    uint256 constant IC0y = 17386686660664256801874676063893764217704068302469533934135566219906644704192;
    
    uint256 constant IC1x = 14221380975530590715147878517041831367963192984231988321881383794761927730845;
    uint256 constant IC1y = 14825291868664801953423316598239663488167188912723395729061235894524090488263;
    
    uint256 constant IC2x = 1501554348069954035421495498704403629905045709936793706551546828497647641769;
    uint256 constant IC2y = 21168460180000473817469025901099055287850108299619317276356757347990762199441;
    
    uint256 constant IC3x = 8735431795095571342562876037783406766884141410582885584032302956583976613934;
    uint256 constant IC3y = 5867973023975053373746875770601016878078959952008658762237210419733065913718;
    
    uint256 constant IC4x = 15394414180185065519644302044832407432386983898897141971736696855361749135086;
    uint256 constant IC4y = 12442432925343616981541948556644224788602936617860318243888972596608939859196;
    
    uint256 constant IC5x = 20463133427665591005433956468983060133605990795115739092317229368362778292040;
    uint256 constant IC5y = 18701013745277422568771228152566661212246826612528601345378453541692213401978;
    
    uint256 constant IC6x = 473910982801405909262474451104364342695936032038564785097335074570029759117;
    uint256 constant IC6y = 8573398340666609291868347960190119336389424650928146559150359910761108093309;
    
    uint256 constant IC7x = 16409177907694635461036854201055769710326518026373266357909214146039455028119;
    uint256 constant IC7y = 17737560061923381559018516427616795266920148574912727296372504412372232301410;
    
    uint256 constant IC8x = 7858422536961121413233421637810170931373909387460961937535397799700788674496;
    uint256 constant IC8y = 9886231663942013396130689703243245778350622408047036392828848454675592164655;
    
    uint256 constant IC9x = 7328210720620351550576755011763018768005979582005265243960688810812272239851;
    uint256 constant IC9y = 3160333471333847558249591807049789969912604653356066245506372364063035138527;
    
    uint256 constant IC10x = 8416398987435598963553655860301543650343763939136654966354553801731083396542;
    uint256 constant IC10y = 18135845012746378413738913347388598559544143796167808560710909959391480566385;
    
    uint256 constant IC11x = 3853937452725923911869654277206527946437161760068565864711256569332108615953;
    uint256 constant IC11y = 14380370411315751096468606753083935052154770822138801944435367252743660631172;
    
    uint256 constant IC12x = 10744636470772830896448180453352755627886450054198604650869489247001777517692;
    uint256 constant IC12y = 1441936301767528082031141738770394984057129576256486521781283838259716192614;
    
    uint256 constant IC13x = 15246190415672454770948377500199547634627103327633483980263159224161171004547;
    uint256 constant IC13y = 5731467159504349302650559044083310790796462265608149939364174473015587952642;
    
    uint256 constant IC14x = 7702896241421194520378127347177325147065148502490524550015019505712061265598;
    uint256 constant IC14y = 7864918352246185567448482473396837806191645307206159638077605858316397710092;
    
    uint256 constant IC15x = 14000139183562571310867967009903387863820842922854070494798594378575216502388;
    uint256 constant IC15y = 18698304555046608286731840251251853672581330242605367456954480834258640941003;
    
    uint256 constant IC16x = 5932530775376658707742457565736958536083050051215213108352388388062154131348;
    uint256 constant IC16y = 12923015928292829401223585878291274944124465926643618027423990124932267869888;
    
    uint256 constant IC17x = 2331534434406690640212144636645575608454677133279294621410752849916577051903;
    uint256 constant IC17y = 15180426739808592978691653480871159562692975886841736582083322884847631656870;
    
    uint256 constant IC18x = 14472650132643361550996083997078062030700242871949110001388001143017686609509;
    uint256 constant IC18y = 6668395962734518641695176173369586915239506176051661338108694317902085748206;
    
    uint256 constant IC19x = 7448197033676196203709213188263353301940713404438838272693318816550754874100;
    uint256 constant IC19y = 2421959330391001728850536037630593961052366602787819976446867328191300440196;
    
    uint256 constant IC20x = 20024408174939367724312537063238357624588972679818173736449912148520393185442;
    uint256 constant IC20y = 2847123718140654495930376021823397723109950922749768943142899542364752850613;
    
    uint256 constant IC21x = 21539859989122787268818817455571883418859244123593961984270495346260110177793;
    uint256 constant IC21y = 18480477675532569060955369461175908860749625332402953770977540151022747205663;
    
    uint256 constant IC22x = 15298424154014436517977799875549948022840910646320879115669726669151070576804;
    uint256 constant IC22y = 1235940467636648620953953486418270732815788894680226242211352450450588246155;
    
    uint256 constant IC23x = 17978316147034515231486359512180937082930630692080397713797228555717368196903;
    uint256 constant IC23y = 18466575809836426462323097361572751121804579692822199353483853955352858356176;
    
    uint256 constant IC24x = 7306356297513896588092112626874536743165615690007531679149346056199608961284;
    uint256 constant IC24y = 13126079089761305488229254836245895781954107120750536928838000521552435610736;
    
    uint256 constant IC25x = 16008914600894445096903796813606901272160786375843100624115452443754532134295;
    uint256 constant IC25y = 21422870743856004478369840531346650175268863746172495079263725244010679839854;
    
    uint256 constant IC26x = 17860690267485913567048806535149455879361804163622318918884294874354935177078;
    uint256 constant IC26y = 14782944592537398750258451582651188397934666234500066955575540015031768625756;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[26] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
